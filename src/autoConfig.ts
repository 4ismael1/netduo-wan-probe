import dotenv from 'dotenv'
import path from 'path'
import { pathToFileURL } from 'url'

export type AutoConfigResult = {
    envPath: string
    outPath: string
    probePort: string
    publicUrl: string
    apiKey: string
    token: string
    allowExternalTarget: string
    envPersisted: boolean
    connectionPersisted: boolean
    apiKeySource: string
    publicUrlSource: string
    warnings: string[]
}

type EnsureAutoConfigModule = {
    ensureAutoConfig: (root: string) => Promise<AutoConfigResult>
}

type RunAutoConfigOptions = {
    fallbackToDotEnv?: boolean
    requireBootstrap?: boolean
    preferServerPortEnv?: boolean
}

async function loadBootstrapModule(rootDir: string): Promise<EnsureAutoConfigModule> {
    const bootstrapModulePath = path.join(rootDir, 'scripts', 'bootstrap-lib.mjs')
    const bootstrapModuleUrl = pathToFileURL(bootstrapModulePath).href
    const dynamicImport = new Function('moduleUrl', 'return import(moduleUrl)') as
        (moduleUrl: string) => Promise<EnsureAutoConfigModule>
    return dynamicImport(bootstrapModuleUrl)
}

export async function runAutoConfig(rootDir: string, options: RunAutoConfigOptions = {}): Promise<AutoConfigResult | null> {
    const fallbackToDotEnv = options.fallbackToDotEnv !== false
    const requireBootstrap = options.requireBootstrap === true
    const preferServerPortEnv = options.preferServerPortEnv === true
    const serverPort = String(process.env.SERVER_PORT || process.env.PORT || '').trim()

    try {
        if (preferServerPortEnv && serverPort && !process.env.PROBE_PORT) {
            process.env.PROBE_PORT = serverPort
        }

        const bootstrapModule = await loadBootstrapModule(rootDir)
        const result = await bootstrapModule.ensureAutoConfig(rootDir)
        dotenv.config({ path: result.envPath, override: false })

        process.env.PROBE_PORT = result.probePort
        process.env.PROBE_PUBLIC_URL = result.publicUrl
        process.env.PROBE_API_KEY = result.apiKey
        process.env.PROBE_ALLOW_EXTERNAL_TARGET = result.allowExternalTarget

        if (preferServerPortEnv && serverPort) {
            process.env.PROBE_PORT = serverPort
        }

        return result
    } catch (error) {
        if (requireBootstrap) throw error
        if (fallbackToDotEnv) dotenv.config()
        return null
    }
}
