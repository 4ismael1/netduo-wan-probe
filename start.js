const fs = require('fs')
const path = require('path')
const { spawn } = require('child_process')

const root = process.cwd()
const pteroEntry = path.join(root, 'src', 'pterodactyl-start.ts')
const autoEntry = path.join(root, 'scripts', 'start-auto.mjs')
const indexEntry = path.join(root, 'src', 'index.ts')
const distEntry = path.join(root, 'dist', 'index.js')

function runNode(args) {
    const child = spawn(process.execPath, args, {
        cwd: root,
        env: process.env,
        stdio: 'inherit',
    })
    child.on('exit', code => process.exit(code ?? 0))
}

if (fs.existsSync(pteroEntry)) {
    runNode(['--import', 'tsx', pteroEntry])
} else if (fs.existsSync(autoEntry)) {
    runNode([autoEntry])
} else if (fs.existsSync(indexEntry)) {
    runNode(['--import', 'tsx', indexEntry])
} else if (fs.existsSync(distEntry)) {
    runNode([distEntry])
} else {
    console.error('No startup entrypoint found.')
    console.error('Expected one of:')
    console.error(' - src/pterodactyl-start.ts')
    console.error(' - scripts/start-auto.mjs')
    console.error(' - src/index.ts')
    console.error(' - dist/index.js')
    process.exit(1)
}
