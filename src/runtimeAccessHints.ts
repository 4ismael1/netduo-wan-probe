export function isCloudRuntime() {
    return [
        'RAILWAY_PROJECT_ID',
        'RAILWAY_ENVIRONMENT',
        'RAILWAY_PUBLIC_DOMAIN',
        'RAILWAY_STATIC_URL',
        'RENDER',
        'RENDER_EXTERNAL_URL',
        'KOYEB_PUBLIC_DOMAIN',
        'VERCEL_URL',
        'FLY_APP_NAME',
        'HEROKU_APP_NAME',
        'K_SERVICE',
    ].some(key => String(process.env[key] || '').trim())
}

export function isPrivateOrLoopbackHost(host: string) {
    const h = String(host || '').trim().toLowerCase()
    if (!h) return true
    if (h === 'localhost') return true
    if (h.startsWith('127.')) return true
    if (h.startsWith('10.')) return true
    if (h.startsWith('192.168.')) return true
    const m = h.match(/^172\.(\d{1,3})\./)
    if (m) {
        const second = Number.parseInt(m[1], 10)
        if (Number.isInteger(second) && second >= 16 && second <= 31) return true
    }
    return false
}

export function printAccessHints(publicUrl: string, publicHost: string) {
    const cloud = isCloudRuntime()
    const privateHost = isPrivateOrLoopbackHost(publicHost)
    console.log('Acceso externo:')
    console.log(` - Endpoint recomendado: ${publicUrl}`)
    if (cloud) {
        console.log(' - Entorno cloud detectado: usa el dominio/URL publica del servicio.')
        console.log(' - No uses 127.0.0.1 ni IPs internas del contenedor (10.x/172.16-31.x/192.168.x).')
        console.log(' - No agregues el puerto interno del contenedor a la URL publica (ejemplo: :8080).')
    } else if (privateHost) {
        console.log(' - El host actual es local/privado; no sera accesible desde Internet.')
        console.log(' - Configura PROBE_PUBLIC_URL con una IP o dominio publico para acceso externo.')
    } else {
        console.log(' - Host publico detectado; puedes usar ese endpoint desde la app cliente.')
    }
}

export function buildDisplayUrl(host: string, port: number, configuredPublicUrl: string | null) {
    if (configuredPublicUrl) return configuredPublicUrl
    const normalizedHost = host === '0.0.0.0' ? '127.0.0.1' : host
    return `http://${normalizedHost}:${port}`
}

export function extractHost(urlText: string) {
    try {
        return new URL(urlText).hostname
    } catch {
        return 'unknown'
    }
}
