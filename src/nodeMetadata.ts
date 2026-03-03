import https from 'https'
import os from 'os'
import { type ProbeConfig } from './config'
import type { NodeMetadata } from './types'

type GeoPayload = {
    ip?: string | null
    city?: string | null
    region?: string | null
    country_name?: string | null
    country?: string | null
    country_code?: string | null
    org?: string | null
    asn?: string | null
}

function requestJson(url: string, timeoutMs: number): Promise<Record<string, unknown> | null> {
    return new Promise(resolve => {
        const req = https.get(url, { timeout: timeoutMs }, res => {
            if (res.statusCode && res.statusCode >= 400) {
                res.resume()
                resolve(null)
                return
            }
            const chunks: Buffer[] = []
            res.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(String(c))))
            res.on('end', () => {
                try {
                    const raw = Buffer.concat(chunks).toString('utf8')
                    const parsed = JSON.parse(raw)
                    if (parsed && typeof parsed === 'object') resolve(parsed as Record<string, unknown>)
                    else resolve(null)
                } catch {
                    resolve(null)
                }
            })
        })
        req.on('timeout', () => {
            req.destroy()
            resolve(null)
        })
        req.on('error', () => resolve(null))
    })
}

function asText(value: unknown): string | null {
    if (typeof value !== 'string') return null
    const trimmed = value.trim()
    return trimmed ? trimmed : null
}

function parsePublicIpFromUrl(publicUrl: string | null): string | null {
    if (!publicUrl) return null
    try {
        const u = new URL(publicUrl)
        const host = u.hostname.trim()
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host
    } catch {}
    return null
}

function normalizeAsn(value: string | null): string | null {
    if (!value) return null
    const cleaned = value.replace(/\s+/g, ' ').trim()
    if (!cleaned) return null
    return cleaned.toUpperCase().startsWith('AS') ? cleaned : `AS${cleaned}`
}

function normalizeProvider(value: string | null): string | null {
    if (!value) return null
    return value.replace(/\s+/g, ' ').trim() || null
}

function fallbackNodeId(publicIp: string | null): string {
    const host = os.hostname().replace(/[^a-zA-Z0-9-_]/g, '').toLowerCase() || 'probe'
    const suffix = publicIp ? publicIp.replace(/\./g, '-') : 'auto'
    return `${host}-${suffix}`
}

async function detectGeoPayload(): Promise<GeoPayload | null> {
    const [primary, secondary] = await Promise.all([
        requestJson('https://ipapi.co/json/', 2500),
        requestJson('https://ipwho.is/', 2500),
    ])

    const base = (primary || secondary) as Record<string, unknown> | null
    if (!base) return null

    const secondaryConnection = (secondary?.connection && typeof secondary.connection === 'object')
        ? secondary.connection as Record<string, unknown>
        : null

    const payload: GeoPayload = {
        ip: asText(base.ip) || asText((secondary || {}).ip),
        city: asText(base.city) || asText((secondary || {}).city),
        region: asText(base.region) || asText((secondary || {}).region),
        country_name: asText(base.country_name) || asText((secondary || {}).country),
        country: asText(base.country) || asText((secondary || {}).country_code),
        org: asText(base.org)
            || asText(secondaryConnection?.org)
            || asText(secondaryConnection?.isp)
            || asText((secondary || {}).isp),
        asn: asText(base.asn) || asText(secondaryConnection?.asn),
    }

    return payload
}

export async function resolveNodeMetadata(cfg: ProbeConfig): Promise<NodeMetadata> {
    const geo = await detectGeoPayload()
    const publicIp = parsePublicIpFromUrl(cfg.publicUrl) || geo?.ip || null

    const providerDetected = normalizeProvider(
        cfg.nodeProvider
        || geo?.org
        || null,
    )
    const regionDetected = cfg.nodeRegion || geo?.region || null
    const cityDetected = cfg.nodeCity || geo?.city || null
    const countryDetected = cfg.nodeCountry || geo?.country_name || geo?.country || null
    const asnDetected = normalizeAsn(cfg.nodeAsn || geo?.asn || null)

    const nodeId = cfg.nodeId || fallbackNodeId(publicIp)
    const label = cfg.nodeLabel
        || [providerDetected || 'NetDuo Probe', regionDetected || countryDetected || 'global']
            .join(' - ')

    return {
        nodeId,
        label,
        provider: providerDetected,
        region: regionDetected,
        city: cityDetected,
        country: countryDetected,
        asn: asnDetected,
        publicIp,
    }
}
