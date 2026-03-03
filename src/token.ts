export function buildConnectToken(input: {
    url: string
    apiKey: string
    createdAt?: string
}) {
    const payload = {
        v: 1,
        kind: 'netduo-wan-probe',
        url: input.url,
        apiKey: input.apiKey,
        createdAt: input.createdAt || new Date().toISOString(),
    }
    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')
    return `NDUO_PROBE_V1:${encoded}`
}
