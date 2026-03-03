import fs from 'fs'
import path from 'path'

export const PROBE_API_VERSION = 'v1.4.0'
// Backward-compatible alias used by existing NetDuo clients.
export const PROBE_API_REVISION = PROBE_API_VERSION
export const PROBE_FEATURE_FLAGS = [
    'tcp-scan',
    'udp-scan',
    'dual-transport-scan',
    'transport-strict-validation',
    'multi-probe-ready',
    'english-only-output',
] as const

function readPackageVersion(rootDir: string): string {
    try {
        const packagePath = path.join(rootDir, 'package.json')
        const raw = fs.readFileSync(packagePath, 'utf8')
        const pkg = JSON.parse(raw) as { version?: unknown }
        if (typeof pkg.version === 'string' && pkg.version.trim()) {
            return pkg.version.trim()
        }
    } catch {
        // ignore
    }
    return 'unknown'
}

export function resolveRuntimeVersionInfo(appName: string) {
    const rootDir = process.cwd()
    const packageVersion = readPackageVersion(rootDir)
    const runtime = `node-${process.version.replace(/^v/, '')}`
    const startedAt = new Date().toISOString()

    return {
        service: appName,
        packageVersion,
        apiVersion: PROBE_API_VERSION,
        apiRevision: PROBE_API_REVISION,
        features: [...PROBE_FEATURE_FLAGS],
        runtime,
        startedAt,
    }
}
