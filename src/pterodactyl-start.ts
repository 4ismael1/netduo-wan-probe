import { buildServer } from './server'
import { loadConfig } from './config'
import { buildConnectToken } from './token'
import { runAutoConfig } from './autoConfig'
import { extractHost, printAccessHints } from './runtimeAccessHints'

async function main() {
    const rootDir = process.cwd()
    const auto = await runAutoConfig(rootDir, {
        fallbackToDotEnv: true,
        requireBootstrap: true,
        preferServerPortEnv: true,
    })
    if (!auto) {
        throw new Error('Auto configuration could not be initialized.')
    }
    const cfg = loadConfig()
    const app = await buildServer(cfg)

    const publicUrl = cfg.publicUrl || auto.publicUrl
    const token = buildConnectToken({ url: publicUrl, apiKey: cfg.apiKey || auto.apiKey })
    const publicHost = extractHost(publicUrl)

    console.log('===============================================')
    console.log(' NetDuo WAN Probe (Pterodactyl mode)')
    console.log('===============================================')
    console.log(`Config file:            ${auto.envPath}`)
    console.log(`Connection file:        ${auto.outPath}`)
    console.log(`Public URL:             ${publicUrl}`)
    console.log(`IP/Host detectado:      ${publicHost}`)
    console.log(`URL source:             ${auto.publicUrlSource}`)
    console.log(`Listening host/port:    ${cfg.host}:${cfg.port}`)
    console.log(`API key source:         ${auto.apiKeySource}`)
    console.log(`API key:                ${cfg.apiKey}`)
    console.log(`Token:                  ${token}`)
    console.log(`External targets:       ${cfg.allowExternalTarget ? 'enabled' : 'disabled'}`)
    console.log(`Persistencia .env:      ${auto.envPersisted ? 'ok' : 'runtime only'}`)
    console.log(`Persistencia token:     ${auto.connectionPersisted ? 'ok' : 'runtime only'}`)
    if (Array.isArray(auto.warnings) && auto.warnings.length) {
        console.log('Warnings:')
        for (const warning of auto.warnings) {
            console.log(` - ${warning}`)
        }
    }
    console.log('-----------------------------------------------')
    printAccessHints(publicUrl, publicHost)
    console.log('===============================================')

    try {
        await app.listen({ host: cfg.host, port: cfg.port })
        app.log.info(`${cfg.appName} listening on ${cfg.host}:${cfg.port}`)
    } catch (err) {
        app.log.error({ err }, 'failed to start probe service')
        process.exit(1)
    }

    const shutdown = async (signal: string) => {
        app.log.info(`received ${signal}, shutting down`)
        try {
            await app.close()
            process.exit(0)
        } catch {
            process.exit(1)
        }
    }

    process.on('SIGTERM', () => void shutdown('SIGTERM'))
    process.on('SIGINT', () => void shutdown('SIGINT'))
}

void main()
