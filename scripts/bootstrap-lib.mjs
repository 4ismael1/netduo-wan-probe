import crypto from 'crypto'
import fs from 'fs'
import https from 'https'
import path from 'path'

function parseEnvText(text) {
    const lines = text.split(/\r?\n/)
    const map = new Map()
    for (const line of lines) {
        if (!line || line.trim().startsWith('#')) continue
        const idx = line.indexOf('=')
        if (idx < 0) continue
        const rawKey = line.slice(0, idx).trim()
        const key = rawKey.startsWith('export ') ? rawKey.slice(7).trim() : rawKey
        const value = line.slice(idx + 1).trim()
        map.set(key, value)
    }
    return { lines, map }
}

function upsertLine(lines, key, value) {
    let replaced = false
    const next = lines.map(line => {
        const idx = line.indexOf('=')
        if (idx < 0) return line
        const k = line.slice(0, idx).trim()
        if (k === key) {
            replaced = true
            return `${key}=${value}`
        }
        return line
    })
    if (!replaced) next.push(`${key}=${value}`)
    return next
}

function randomApiKey() {
    return crypto.randomBytes(24).toString('hex')
}

function normalizeValue(raw) {
    const text = String(raw || '').trim()
    if (!text) return ''
    if (
        (text.startsWith('"') && text.endsWith('"'))
        || (text.startsWith("'") && text.endsWith("'"))
    ) {
        return text.slice(1, -1).trim()
    }
    return text
}

function firstNonEmpty(...values) {
    for (const value of values) {
        const text = normalizeValue(value)
        if (text) return text
    }
    return ''
}

function toBoolText(value, fallback = true) {
    const text = normalizeValue(value).toLowerCase()
    if (['1', 'true', 'yes', 'on'].includes(text)) return 'true'
    if (['0', 'false', 'no', 'off'].includes(text)) return 'false'
    return fallback ? 'true' : 'false'
}

function isPlaceholderSecret(value) {
    const text = normalizeValue(value).toLowerCase()
    if (!text) return true
    const normalized = text.replace(/[\s_-]+/g, '')
    if (normalized.length < 8) return true
    const placeholders = new Set([
        'changeme',
        'replace',
        'replaceit',
        'default',
        'dummy',
        'none',
        'null',
        'undefined',
        'apikey',
        'token',
        'yourapikey',
        'yourtoken',
        'setme',
    ])
    if (placeholders.has(normalized)) return true
    if (normalized.includes('your') && normalized.includes('key')) return true
    if (normalized.includes('change') && normalized.includes('me')) return true
    return false
}

function isPlaceholderUrl(value) {
    const text = normalizeValue(value).toLowerCase()
    if (!text) return true
    if (text.includes('your_vps_ip') || text.includes('your-vps-ip')) return true
    if (text.includes('example.com') || text.includes('localhost')) return true
    return false
}

function normalizePort(raw, fallback = '9443') {
    const text = normalizeValue(raw)
    if (!/^\d+$/.test(text)) return fallback
    const value = Number.parseInt(text, 10)
    if (!Number.isInteger(value) || value < 1 || value > 65535) return fallback
    return String(value)
}

function normalizeUrl(urlText, fallbackProtocol = 'http') {
    const raw = normalizeValue(urlText)
    if (!raw) return ''
    const hasProtocol = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw)
    const candidate = hasProtocol ? raw : `${fallbackProtocol}://${raw}`
    try {
        const u = new URL(candidate)
        return u.toString().replace(/\/$/, '')
    } catch {
        return raw
    }
}

function withPortIfExplicit(urlText, probePort) {
    const raw = normalizeValue(urlText)
    if (!raw) return ''
    const hasProtocol = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw)
    const candidate = hasProtocol ? raw : `http://${raw}`
    try {
        const u = new URL(candidate)
        if (u.port) {
            u.port = String(probePort)
        }
        return u.toString().replace(/\/$/, '')
    } catch {
        return raw
    }
}

function detectPlatformPublicUrl() {
    const candidates = [
        normalizeUrl(process.env.RAILWAY_STATIC_URL, 'https'),
        normalizeUrl(process.env.RAILWAY_PUBLIC_DOMAIN, 'https'),
        normalizeUrl(process.env.RENDER_EXTERNAL_URL, 'https'),
        normalizeUrl(process.env.RENDER_EXTERNAL_HOSTNAME, 'https'),
        normalizeUrl(process.env.KOYEB_PUBLIC_DOMAIN, 'https'),
        normalizeUrl(process.env.VERCEL_URL, 'https'),
    ]
    return candidates.find(Boolean) || ''
}

function toBase64Url(input) {
    return Buffer.from(input, 'utf8')
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '')
}

function requestText(url, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { timeout: timeoutMs }, res => {
            if (res.statusCode && res.statusCode >= 400) {
                res.resume()
                return reject(new Error(`HTTP ${res.statusCode}`))
            }
            let body = ''
            res.on('data', c => { body += c.toString() })
            res.on('end', () => resolve(body.trim()))
        })
        req.on('timeout', () => req.destroy(new Error('timeout')))
        req.on('error', reject)
    })
}

async function detectPublicIp() {
    const endpoints = [
        'https://api.ipify.org?format=text',
        'https://ifconfig.me/ip',
        'https://ipv4.icanhazip.com',
    ]
    for (const endpoint of endpoints) {
        try {
            const ip = await requestText(endpoint, 5000)
            if (ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip
        } catch {}
    }
    return null
}

function resolveApiKey(envMap) {
    const runtimeApiKey = normalizeValue(process.env.PROBE_API_KEY)
    if (runtimeApiKey && !isPlaceholderSecret(runtimeApiKey)) {
        return { value: runtimeApiKey, source: 'runtime-env' }
    }

    const fileApiKey = normalizeValue(envMap.get('PROBE_API_KEY'))
    if (fileApiKey && !isPlaceholderSecret(fileApiKey)) {
        return { value: fileApiKey, source: 'env-file' }
    }

    return { value: randomApiKey(), source: 'generated' }
}

function resolveAllowExternalTarget(envMap) {
    const runtimeValue = normalizeValue(process.env.PROBE_ALLOW_EXTERNAL_TARGET)
    if (runtimeValue) return toBoolText(runtimeValue, true)
    const fileValue = normalizeValue(envMap.get('PROBE_ALLOW_EXTERNAL_TARGET'))
    if (fileValue) return toBoolText(fileValue, true)
    return 'true'
}

function resolveProbePort(envMap) {
    const runtimePort = normalizePort(firstNonEmpty(
        process.env.PROBE_PORT,
        process.env.PORT,
        process.env.SERVER_PORT,
    ), '')
    const filePort = normalizePort(firstNonEmpty(
        envMap.get('PROBE_PORT'),
        envMap.get('PORT'),
        envMap.get('SERVER_PORT'),
    ), '')
    return runtimePort || filePort || '9443'
}

async function resolvePublicUrl(envMap, probePort) {
    const runtimePublicUrl = normalizeValue(process.env.PROBE_PUBLIC_URL)
    if (runtimePublicUrl && !isPlaceholderUrl(runtimePublicUrl)) {
        return { value: withPortIfExplicit(runtimePublicUrl, probePort), source: 'runtime-env' }
    }

    const platformPublicUrl = detectPlatformPublicUrl()
    if (platformPublicUrl) {
        return { value: platformPublicUrl, source: 'platform-domain' }
    }

    const filePublicUrl = normalizeValue(envMap.get('PROBE_PUBLIC_URL'))
    if (filePublicUrl && !isPlaceholderUrl(filePublicUrl)) {
        return { value: withPortIfExplicit(filePublicUrl, probePort), source: 'env-file' }
    }

    const ip = await detectPublicIp()
    if (ip) {
        return { value: `http://${ip}:${probePort}`, source: 'public-ip' }
    }

    return { value: `http://127.0.0.1:${probePort}`, source: 'local-fallback' }
}

function tryWriteFile(filePath, text, warnings, label) {
    try {
        fs.writeFileSync(filePath, text, 'utf8')
        return true
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        warnings.push(`Could not write ${label}: ${message}`)
        return false
    }
}

function applyRuntimeEnv(values) {
    process.env.PROBE_PORT = values.probePort
    process.env.PROBE_PUBLIC_URL = values.publicUrl
    process.env.PROBE_API_KEY = values.apiKey
    process.env.PROBE_ALLOW_EXTERNAL_TARGET = values.allowExternalTarget
}

export async function ensureAutoConfig(rootDir) {
    const envPath = path.join(rootDir, '.env')
    const examplePath = path.join(rootDir, '.env.example')
    const outPath = path.join(rootDir, 'netduo_probe_connection.txt')
    const warnings = []
    let envPersisted = false

    if (!fs.existsSync(envPath)) {
        try {
            if (fs.existsSync(examplePath)) {
                fs.copyFileSync(examplePath, envPath)
            } else {
                fs.writeFileSync(envPath, '', 'utf8')
            }
            envPersisted = true
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            warnings.push(`Could not initialize .env: ${message}`)
        }
    }

    let currentText = ''
    try {
        if (fs.existsSync(envPath)) {
            currentText = fs.readFileSync(envPath, 'utf8')
        }
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        warnings.push(`Could not read .env: ${message}`)
    }

    const { lines, map } = parseEnvText(currentText)

    const apiKeyResolved = resolveApiKey(map)
    const apiKey = apiKeyResolved.value
    const probePort = resolveProbePort(map)
    const publicUrlResolved = await resolvePublicUrl(map, probePort)
    const publicUrl = publicUrlResolved.value
    const allowExternalTarget = resolveAllowExternalTarget(map)

    let updated = lines
    updated = upsertLine(updated, 'PROBE_API_KEY', apiKey)
    updated = upsertLine(updated, 'PROBE_PORT', probePort)
    updated = upsertLine(updated, 'PROBE_PUBLIC_URL', publicUrl)
    updated = upsertLine(updated, 'PROBE_ALLOW_EXTERNAL_TARGET', allowExternalTarget)
    if (!updated[updated.length - 1]?.trim()) {
        // keep as-is
    }
    const nextEnvText = `${updated.join('\n').replace(/\n+$/g, '')}\n`
    const wroteEnv = tryWriteFile(envPath, nextEnvText, warnings, '.env')
    envPersisted = envPersisted || wroteEnv

    const payload = JSON.stringify({
        v: 1,
        kind: 'netduo-wan-probe',
        url: publicUrl,
        apiKey,
        createdAt: new Date().toISOString(),
    })
    const token = `NDUO_PROBE_V1:${toBase64Url(payload)}`

    const outputText = [
        `NETDUO_PROBE_URL=${publicUrl}`,
        `NETDUO_PROBE_KEY=${apiKey}`,
        `NETDUO_CONNECT_TOKEN=${token}`,
        `NETDUO_PROBE_PORT=${probePort}`,
        `NETDUO_PROBE_ALLOW_EXTERNAL_TARGET=${allowExternalTarget}`,
        '',
    ].join('\n')
    const connectionPersisted = tryWriteFile(outPath, outputText, warnings, 'connection file')

    applyRuntimeEnv({
        probePort,
        publicUrl,
        apiKey,
        allowExternalTarget,
    })

    return {
        envPath,
        outPath,
        probePort,
        publicUrl,
        apiKey,
        token,
        allowExternalTarget,
        envPersisted,
        connectionPersisted,
        apiKeySource: apiKeyResolved.source,
        publicUrlSource: publicUrlResolved.source,
        warnings,
    }
}
