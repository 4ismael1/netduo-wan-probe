import assert from 'node:assert/strict'
import { test } from 'node:test'
import { buildServer } from '../src/server'
import type { ProbeConfig } from '../src/config'
import { PROBE_API_REVISION, PROBE_API_VERSION } from '../src/version'

function baseCfg(overrides: Partial<ProbeConfig> = {}): ProbeConfig {
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
        quickTimeoutMs: 500,
        advancedTimeoutMs: 700,
        deepTimeoutMs: 900,
        quickUdpTimeoutMs: 900,
        advancedUdpTimeoutMs: 1100,
        deepUdpTimeoutMs: 1300,
        maxCustomPorts: 4096,
        maxCustomUdpPorts: 4096,
        jobTtlMinutes: 45,
        rateLimitMax: 500,
        rateLimitTimeWindow: '1 minute',
        quickPorts: [22, 80],
        advancedPorts: [22, 80, 443],
        deepPorts: [22, 80, 443, 8080],
        quickUdpPorts: [53, 123],
        advancedUdpPorts: [53, 123, 161],
        deepUdpPorts: [53, 123, 161, 1900],
        allowedPorts: null,
        enforceAllowedPorts: false,
        enableUdpScan: true,
        enableHttpProbe: false,
        enableTlsProbe: false,
        enableBannerProbe: false,
        nodeId: 'test-node',
        nodeLabel: 'Test Node',
        nodeProvider: 'Test',
        nodeRegion: 'Local',
        nodeCity: 'Local',
        nodeCountry: 'Local',
        nodeAsn: 'AS0',
        ...overrides,
    }
}

test('scan/start rejects explicit UDP transport when probe has UDP disabled', async () => {
    const app = await buildServer(baseCfg({ enableUdpScan: false }))
    try {
        const res = await app.inject({
            method: 'POST',
            url: '/scan/start',
            headers: {
                authorization: 'Bearer test-key',
                'content-type': 'application/json',
            },
            payload: {
                mode: 'advanced',
                profile: 'balanced',
                transport: 'udp',
                target: '198.51.100.20',
                udpPorts: [53, 123],
            },
        })

        assert.equal(res.statusCode, 400)
        const body = res.json()
        assert.equal(body.ok, false)
        assert.equal(body.error, 'UDP disabled')
    } finally {
        await app.close()
    }
})

test('scan/start still accepts auto transport when UDP is disabled and resolves to TCP', async () => {
    const app = await buildServer(baseCfg({ enableUdpScan: false }))
    try {
        const res = await app.inject({
            method: 'POST',
            url: '/scan/start',
            headers: {
                authorization: 'Bearer test-key',
                'content-type': 'application/json',
            },
            payload: {
                mode: 'quick',
                profile: 'balanced',
                transport: 'auto',
                target: '198.51.100.20',
                ports: [22],
            },
        })

        assert.equal(res.statusCode, 202)
        const body = res.json()
        assert.equal(body.transport, 'tcp')
        assert.deepEqual(body.tcpPorts, [22])
        assert.deepEqual(body.udpPorts, [])
    } finally {
        await app.close()
    }
})

test('scan/start resolves auto to TCP even on deep mode when UDP is enabled', async () => {
    const app = await buildServer(baseCfg({ enableUdpScan: true }))
    try {
        const res = await app.inject({
            method: 'POST',
            url: '/scan/start',
            headers: {
                authorization: 'Bearer test-key',
                'content-type': 'application/json',
            },
            payload: {
                mode: 'deep',
                profile: 'balanced',
                transport: 'auto',
                target: '198.51.100.20',
                ports: [22, 80, 443],
                udpPorts: [53, 123],
            },
        })

        assert.equal(res.statusCode, 202)
        const body = res.json()
        assert.equal(body.transport, 'tcp')
        assert.deepEqual(body.tcpPorts, [22, 80, 443])
        assert.deepEqual(body.udpPorts, [])
    } finally {
        await app.close()
    }
})

test('version endpoint is public and exposes api revision', async () => {
    const app = await buildServer(baseCfg({ enableUdpScan: true }))
    try {
        const res = await app.inject({
            method: 'GET',
            url: '/version',
        })

        assert.equal(res.statusCode, 200)
        const body = res.json()
        assert.equal(body.ok, true)
        assert.equal(body.apiVersion, PROBE_API_VERSION)
        assert.equal(body.apiRevision, PROBE_API_REVISION)
        assert.ok(Array.isArray(body.features))
        assert.equal(body.capabilities?.transport?.tcp, true)
        assert.equal(body.capabilities?.transport?.udp, true)
        assert.equal(body.capabilities?.transport?.both, true)
        assert.equal(body.capabilities?.transport?.auto, true)
        assert.equal(body.capabilities?.transport?.default, 'tcp')
    } finally {
        await app.close()
    }
})
