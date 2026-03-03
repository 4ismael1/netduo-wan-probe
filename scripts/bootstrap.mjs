import path from 'path'
import { fileURLToPath } from 'url'
import { ensureAutoConfig } from './bootstrap-lib.mjs'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const root = path.resolve(__dirname, '..')

const result = await ensureAutoConfig(root)

console.log('===============================================')
console.log(' NetDuo WAN Probe auto-config listo')
console.log('===============================================')
console.log(`URL:   ${result.publicUrl}`)
console.log(`URL source: ${result.publicUrlSource}`)
console.log(`PORT:  ${result.probePort}`)
console.log(`KEY source: ${result.apiKeySource}`)
console.log(`KEY:   ${result.apiKey}`)
console.log(`TOKEN: ${result.token}`)
console.log(`EXTERNAL TARGETS: ${result.allowExternalTarget}`)
console.log(`ENV persisted: ${result.envPersisted ? 'yes' : 'no (runtime only)'}`)
console.log(`CONNECT persisted: ${result.connectionPersisted ? 'yes' : 'no (runtime only)'}`)
if (Array.isArray(result.warnings) && result.warnings.length) {
    console.log('Warnings:')
    for (const warning of result.warnings) {
        console.log(` - ${warning}`)
    }
}
console.log('-----------------------------------------------')
console.log(`Archivo de conexion: ${result.outPath}`)
console.log(`Archivo de config:   ${result.envPath}`)
console.log('-----------------------------------------------')
console.log('Si quieres cambiar puerto o seguridad, edita .env')
