import assert from 'node:assert/strict'
import { test } from 'node:test'
import dgram from 'node:dgram'
import net from 'node:net'
import { performWanScan } from '../src/scanner'
import type { ProbeConfig } from '../src/config'

function baseCfg(): ProbeConfig {
    return {
        appName: 'NetDuo WAN Probe Test',
        host: '127.0.0.1',
        port: 9443,
        logLevel: 'error',
        trustProxy: false,
        apiKey: 'test-key',
        publicUrl: null,
        allowExternalTarget: true,
        requirePublicTarget: false,
        profileDefault: 'balanced',
        scanTransportDefault: 'tcp',
        requestTimeoutMs: 800,
        quickRetries: 1,
        advancedRetries: 1,
        deepRetries: 1,
        quickUdpRetries: 2,
        advancedUdpRetries: 2,
        deepUdpRetries: 2,
        scanConcurrency: 8,
        udpScanConcurrency: 4,
        quickConcurrency: 4,
        advancedConcurrency: 8,
        deepConcurrency: 8,
        quickUdpConcurrency: 2,
        advancedUdpConcurrency: 4,
        deepUdpConcurrency: 4,
        quickTimeoutMs: 800,
        advancedTimeoutMs: 900,
        deepTimeoutMs: 1000,
        quickUdpTimeoutMs: 900,
        advancedUdpTimeoutMs: 1100,
        deepUdpTimeoutMs: 1400,
        maxCustomPorts: 4096,
        maxCustomUdpPorts: 4096,
        jobTtlMinutes: 45,
        rateLimitMax: 100,
        rateLimitTimeWindow: '1 minute',
        quickPorts: [22, 80, 443],
        advancedPorts: [22, 80, 443, 8080],
        deepPorts: [22, 80, 443, 8080, 8443],
        quickUdpPorts: [53, 123, 161],
        advancedUdpPorts: [53, 123, 161, 1900],
        deepUdpPorts: [53, 123, 161, 1900, 5060],
        allowedPorts: null,
        enforceAllowedPorts: false,
        enableUdpScan: true,
        enableHttpProbe: false,
        enableTlsProbe: false,
        enableBannerProbe: false,
        defaultLanguage: 'en',
        nodeId: null,
        nodeLabel: null,
        nodeProvider: null,
        nodeRegion: null,
        nodeCity: null,
        nodeCountry: null,
        nodeAsn: null,
    }
}

function listenUdpEcho() {
    return new Promise<{ socket: dgram.Socket; port: number }>((resolve, reject) => {
        const socket = dgram.createSocket('udp4')
        socket.on('error', reject)
        socket.on('message', (_msg, rinfo) => {
            socket.send(Buffer.from('ok'), rinfo.port, rinfo.address)
        })
        socket.bind(0, '127.0.0.1', () => {
            const address = socket.address()
            if (typeof address === 'string') {
                reject(new Error('Unexpected unix socket address'))
                return
            }
            resolve({ socket, port: address.port })
        })
    })
}

function listenTcp() {
    return new Promise<{ server: net.Server; port: number }>((resolve, reject) => {
        const server = net.createServer(socket => {
            socket.on('error', () => {})
            socket.end('hello')
        })
        server.on('error', reject)
        server.listen(0, '127.0.0.1', () => {
            const address = server.address()
            if (!address || typeof address === 'string') {
                reject(new Error('Unexpected tcp address'))
                return
            }
            resolve({ server, port: address.port })
        })
    })
}

test('UDP transport detects open local UDP service', async () => {
    const cfg = baseCfg()
    const { socket, port } = await listenUdpEcho()
    const phases: string[] = []

    try {
        const result = await performWanScan({
            mode: 'quick',
            profile: 'balanced',
            transport: 'udp',
            target: '127.0.0.1',
            observedIp: '127.0.0.1',
            tcpPorts: [],
            udpPorts: [port],
            cfg,
            onProgress: progress => {
                phases.push(progress.phase)
            },
        })

        assert.equal(result.transport, 'udp')
        assert.equal(result.openUdpCount, 1)
        assert.equal(result.openTcpCount, 0)
        assert.equal(result.openCount, 1)
        assert.equal(result.results.length, 1)
        assert.equal(result.results[0].protocol, 'udp')
        assert.equal(result.results[0].state, 'open')
        assert.ok(phases.includes('udp_sweep'))
    } finally {
        await new Promise<void>(resolve => socket.close(() => resolve()))
    }
})

test('Both transport scans TCP and UDP on same port and keeps split counters', async () => {
    const cfg = baseCfg()
    const { server, port } = await listenTcp()
    const udpSocket = dgram.createSocket('udp4')
    udpSocket.on('message', (_msg, rinfo) => {
        udpSocket.send(Buffer.from('ok'), rinfo.port, rinfo.address)
    })
    await new Promise<void>((resolve, reject) => {
        udpSocket.once('error', reject)
        udpSocket.bind(port, '127.0.0.1', () => resolve())
    })

    try {
        const result = await performWanScan({
            mode: 'advanced',
            profile: 'balanced',
            transport: 'both',
            target: '127.0.0.1',
            observedIp: '127.0.0.1',
            tcpPorts: [port],
            udpPorts: [port],
            cfg,
        })

        assert.equal(result.transport, 'both')
        assert.equal(result.tcpPorts.length, 1)
        assert.equal(result.udpPorts.length, 1)
        assert.equal(result.ports.length, 1)
        assert.equal(result.openTcpCount, 1)
        assert.equal(result.openUdpCount, 1)
        assert.equal(result.openCount, 2)
        assert.equal(result.results.length, 2)
        assert.deepEqual(
            result.results.map(r => r.protocol).sort(),
            ['tcp', 'udp'],
        )
    } finally {
        await new Promise<void>(resolve => server.close(() => resolve()))
        await new Promise<void>(resolve => udpSocket.close(() => resolve()))
    }
})
