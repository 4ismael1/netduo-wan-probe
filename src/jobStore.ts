import { randomUUID } from 'crypto'
import type { ProbeLanguage, ScanJob, ScanMode, ScanProfile, ScanProgress, ScanTransport, WanScanResult } from './types'

export class JobStore {
    private jobs = new Map<string, ScanJob>()

    constructor(
        private readonly ttlMinutes: number,
        private readonly maxJobs: number,
    ) {}

    private progressMessage(language: ProbeLanguage, key: 'queued' | 'tcp' | 'udp' | 'done'): string {
        if (language === 'es') {
            if (key === 'queued') return 'Scan en cola'
            if (key === 'tcp') return 'Escaneo TCP en progreso'
            if (key === 'udp') return 'Escaneo UDP en progreso'
            return 'Escaneo completado'
        }
        if (key === 'queued') return 'Scan queued'
        if (key === 'tcp') return 'TCP sweep in progress'
        if (key === 'udp') return 'UDP sweep in progress'
        return 'Scan completed'
    }

    private buildInitialProgress(
        totalPorts: number,
        totalTcpPorts: number,
        totalUdpPorts: number,
        transport: ScanTransport,
        language: ProbeLanguage,
    ): ScanProgress {
        const now = new Date().toISOString()
        return {
            phase: 'queued',
            message: this.progressMessage(language, 'queued'),
            language,
            transport,
            totalPorts,
            scannedPorts: 0,
            openPorts: 0,
            closedPorts: 0,
            filteredPorts: 0,
            totalTcpPorts,
            totalUdpPorts,
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
            startedAt: now,
            updatedAt: now,
        }
    }

    create(input: {
        mode: ScanMode
        profile: ScanProfile
        transport: ScanTransport
        language: ProbeLanguage
        target: string
        observedIp: string
        ports: number[]
        tcpPorts: number[]
        udpPorts: number[]
    }): ScanJob {
        this.cleanup()
        const id = randomUUID()
        const totalPorts = input.tcpPorts.length + input.udpPorts.length
        const job: ScanJob = {
            id,
            status: 'queued',
            phase: 'queued',
            mode: input.mode,
            profile: input.profile,
            transport: input.transport,
            language: input.language,
            target: input.target,
            observedIp: input.observedIp,
            ports: input.ports,
            tcpPorts: input.tcpPorts,
            udpPorts: input.udpPorts,
            progress: this.buildInitialProgress(totalPorts, input.tcpPorts.length, input.udpPorts.length, input.transport, input.language),
            createdAt: new Date().toISOString(),
        }
        this.jobs.set(id, job)
        this.trim()
        return job
    }

    markRunning(id: string) {
        const job = this.jobs.get(id)
        if (!job) return
        job.status = 'running'
        job.startedAt = new Date().toISOString()
        job.progress.startedAt = job.startedAt
        if (job.phase === 'queued') {
            const initialPhase = job.transport === 'udp' ? 'udp_sweep' : 'tcp_sweep'
            job.phase = initialPhase
            job.progress.phase = initialPhase
            job.progress.message = initialPhase === 'udp_sweep'
                ? this.progressMessage(job.language, 'udp')
                : this.progressMessage(job.language, 'tcp')
            job.progress.updatedAt = new Date().toISOString()
            job.progress.percent = Math.max(job.progress.percent, 1)
        }
        this.jobs.set(id, job)
    }

    updateProgress(id: string, progress: ScanProgress) {
        const job = this.jobs.get(id)
        if (!job) return
        job.status = job.status === 'queued' ? 'running' : job.status
        job.phase = progress.phase
        job.progress = progress
        if (!job.startedAt) job.startedAt = progress.startedAt || new Date().toISOString()
        this.jobs.set(id, job)
    }

    markDone(id: string, result: WanScanResult) {
        const job = this.jobs.get(id)
        if (!job) return
        job.status = 'done'
        job.phase = 'done'
        job.finishedAt = new Date().toISOString()
        job.durationMs = result.durationMs
        job.result = result
        job.progress = {
            phase: 'done',
            message: this.progressMessage(job.language, 'done'),
            language: result.language || job.language,
            transport: result.transport,
            totalPorts: result.tcpPorts.length + result.udpPorts.length,
            scannedPorts: result.tcpPorts.length + result.udpPorts.length,
            openPorts: result.openCount,
            closedPorts: result.closedCount,
            filteredPorts: result.filteredCount,
            totalTcpPorts: result.tcpPorts.length,
            totalUdpPorts: result.udpPorts.length,
            scannedTcpPorts: result.tcpPorts.length,
            scannedUdpPorts: result.udpPorts.length,
            openTcpPorts: result.openTcpCount,
            closedTcpPorts: result.closedTcpCount,
            filteredTcpPorts: result.filteredTcpCount,
            openUdpPorts: result.openUdpCount,
            closedUdpPorts: result.closedUdpCount,
            filteredUdpPorts: result.filteredUdpCount,
            servicePortsScanned: result.results.filter(v => Boolean(v.http || v.tls || v.banner)).length,
            percent: 100,
            startedAt: result.startedAt,
            updatedAt: result.finishedAt,
        }
        this.jobs.set(id, job)
    }

    markError(id: string, message: string) {
        const job = this.jobs.get(id)
        if (!job) return
        job.status = 'error'
        job.phase = 'error'
        job.finishedAt = new Date().toISOString()
        job.error = message
        job.progress = {
            ...job.progress,
            phase: 'error',
            message,
            percent: job.progress.percent || 0,
            updatedAt: job.finishedAt,
        }
        this.jobs.set(id, job)
    }

    get(id: string) {
        this.cleanup()
        return this.jobs.get(id) || null
    }

    private trim() {
        if (this.jobs.size <= this.maxJobs) return
        const entries = [...this.jobs.values()]
            .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt))
        const overflow = this.jobs.size - this.maxJobs
        for (let i = 0; i < overflow; i++) {
            this.jobs.delete(entries[i].id)
        }
    }

    cleanup() {
        const ttlMs = this.ttlMinutes * 60 * 1000
        const now = Date.now()
        for (const [id, job] of this.jobs.entries()) {
            const ref = Date.parse(job.finishedAt || job.createdAt)
            if (Number.isFinite(ref) && now - ref > ttlMs) this.jobs.delete(id)
        }
    }
}
