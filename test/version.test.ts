import assert from 'node:assert/strict'
import { test } from 'node:test'
import { PROBE_API_REVISION, PROBE_API_VERSION, resolveRuntimeVersionInfo } from '../src/version'

test('api version uses semantic format and keeps revision alias', () => {
    assert.match(PROBE_API_VERSION, /^v\d+\.\d+\.\d+$/)
    assert.equal(PROBE_API_REVISION, PROBE_API_VERSION)
})

test('runtime version info exposes apiVersion and apiRevision', () => {
    const info = resolveRuntimeVersionInfo('NetDuo WAN Probe Test')
    assert.equal(info.apiVersion, PROBE_API_VERSION)
    assert.equal(info.apiRevision, PROBE_API_VERSION)
    assert.equal(info.service, 'NetDuo WAN Probe Test')
    assert.ok(Array.isArray(info.features))
})
