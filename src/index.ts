import dotenv from 'dotenv'
import { buildServer } from './server'
import { loadConfig } from './config'
import { buildConnectToken } from './token'
import { runAutoConfig } from './autoConfig'
import { buildDisplayUrl, extractHost, printAccessHints } from './runtimeAccessHints'

async function main() {
    const rootDir = process.cwd()
    const auto = await runAutoConfig(rootDir, {
        fallbackToDotEnv: true,
        requireBootstrap: false,
        preferServerPortEnv: false,
    })
    const cfg = loadConfig()
    const app = await buildServer(cfg)

    try {
        await app.listen({ host: cfg.host, port: cfg.port })
        app.log.info(`${cfg.appName} listening on ${cfg.host}:${cfg.port}`)
        const publicUrl = cfg.publicUrl || auto?.publicUrl || buildDisplayUrl(cfg.host, cfg.port, cfg.publicUrl)
        const token = buildConnectToken({ url: publicUrl, apiKey: cfg.apiKey })
        const publicHost = extractHost(publicUrl)

        console.log('===============================================')
        console.log(` ${cfg.appName}`)
        console.log('===============================================')
        console.log(`URL actual:             ${publicUrl}`)
        console.log(`IP/Host detectado:      ${publicHost}`)
        console.log(`Puerto actual:          ${cfg.port}`)
        if (auto) {
            console.log(`Origen URL:             ${auto.publicUrlSource}`)
            console.log(`Origen API key:         ${auto.apiKeySource}`)
        }
        console.log(`API key:                ${cfg.apiKey}`)
        console.log(`Token:                  ${token}`)
        console.log(`External targets:       ${cfg.allowExternalTarget ? 'enabled' : 'disabled'}`)
        console.log(`Default transport:      ${cfg.scanTransportDefault}`)
        console.log(`Transport support:      tcp=enabled | udp=${cfg.enableUdpScan ? 'enabled' : 'disabled'} | both=${cfg.enableUdpScan ? 'enabled' : 'disabled'} | auto=tcp`)
        if (auto) {
            console.log(`Persistencia .env:      ${auto.envPersisted ? 'ok' : 'runtime only'}`)
            console.log(`Persistencia token:     ${auto.connectionPersisted ? 'ok' : 'runtime only'}`)
            if (Array.isArray(auto.warnings) && auto.warnings.length) {
                console.log('Advertencias:')
                for (const warning of auto.warnings) {
                    console.log(` - ${warning}`)
                }
            }
        }
        console.log('-----------------------------------------------')
        printAccessHints(publicUrl, publicHost)
        console.log('===============================================')
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
