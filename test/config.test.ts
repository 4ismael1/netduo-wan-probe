import assert from 'node:assert/strict'
import { test } from 'node:test'
import { loadConfig } from '../src/config'

function withEnv<T>(env: Record<string, string | undefined>, run: () => T): T {
    const prev = new Map<string, string | undefined>()
    for (const [key, value] of Object.entries(env)) {
        prev.set(key, process.env[key])
        if (value == null) delete process.env[key]
        else process.env[key] = value
    }
    try {
        return run()
    } finally {
        for (const [key, value] of prev.entries()) {
            if (value == null) delete process.env[key]
            else process.env[key] = value
        }
    }
}

test('loadConfig parses transport defaults and UDP toggles', () => {
    const cfg = withEnv({
        PROBE_SCAN_TRANSPORT_DEFAULT: 'both',
        PROBE_ENABLE_UDP_SCAN: 'true',
        PROBE_REQUIRE_PUBLIC_TARGET: 'false',
        PROBE_QUICK_UDP_PORTS: '53, 123, 161, 161',
        PROBE_MAX_CUSTOM_UDP_PORTS: '2048',
    }, () => loadConfig())

    assert.equal(cfg.scanTransportDefault, 'both')
    assert.equal(cfg.enableUdpScan, true)
    assert.deepEqual(cfg.quickUdpPorts, [53, 123, 161])
    assert.equal(cfg.maxCustomUdpPorts, 2048)
})

test('loadConfig falls back to tcp when transport default is invalid', () => {
    const cfg = withEnv({
        PROBE_SCAN_TRANSPORT_DEFAULT: 'invalid-value',
        PROBE_ENABLE_UDP_SCAN: 'false',
    }, () => loadConfig())

    assert.equal(cfg.scanTransportDefault, 'tcp')
    assert.equal(cfg.enableUdpScan, false)
})

