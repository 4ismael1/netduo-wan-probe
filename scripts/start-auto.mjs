import { spawn } from 'child_process'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { ensureAutoConfig } from './bootstrap-lib.mjs'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const root = path.resolve(__dirname, '..')
const serverEntry = path.join(root, 'src', 'index.ts')
const distEntry = path.join(root, 'dist', 'index.js')

function isCloudRuntime() {
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

function isPrivateOrLoopbackHost(host) {
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

function printAccessHints(publicUrl, publicHost) {
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

const result = await ensureAutoConfig(root)
let publicHost = 'unknown'
try {
    publicHost = new URL(result.publicUrl).hostname
} catch {}

console.log('===============================================')
console.log(' NetDuo WAN Probe')
console.log('===============================================')
console.log(`Servicio configurado en: ${result.envPath}`)
console.log(`Conexion para NetDuo:   ${result.outPath}`)
console.log(`URL actual:             ${result.publicUrl}`)
console.log(`IP/Host detectado:      ${publicHost}`)
console.log(`Puerto actual:          ${result.probePort}`)
console.log(`Origen URL:             ${result.publicUrlSource}`)
console.log(`Origen API key:         ${result.apiKeySource}`)
console.log(`API key:                ${result.apiKey}`)
console.log(`Token:                  ${result.token}`)
console.log(`External targets:       ${result.allowExternalTarget}`)
console.log(`Persistencia .env:      ${result.envPersisted ? 'ok' : 'runtime only'}`)
console.log(`Persistencia token:     ${result.connectionPersisted ? 'ok' : 'runtime only'}`)
if (Array.isArray(result.warnings) && result.warnings.length) {
    console.log('Advertencias:')
    for (const warning of result.warnings) {
        console.log(` - ${warning}`)
    }
}
console.log('-----------------------------------------------')
printAccessHints(result.publicUrl, publicHost)
console.log('-----------------------------------------------')
console.log('Para cambiar puerto u opciones: edita .env')
console.log('Iniciando servicio...')
console.log('===============================================')

const childEnv = {
    ...process.env,
    PROBE_PORT: result.probePort,
    PROBE_PUBLIC_URL: result.publicUrl,
    PROBE_API_KEY: result.apiKey,
    PROBE_ALLOW_EXTERNAL_TARGET: result.allowExternalTarget,
}

const commandArgs = fs.existsSync(serverEntry)
    ? ['--import', 'tsx', serverEntry]
    : [distEntry]

const child = spawn(process.execPath, commandArgs, {
    cwd: root,
    stdio: 'inherit',
    env: childEnv,
})

child.on('exit', code => {
    process.exit(code ?? 0)
})
