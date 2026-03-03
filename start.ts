import path from 'path'
import { spawn } from 'child_process'

const startJs = path.join(process.cwd(), 'start.js')
const child = spawn(process.execPath, [startJs], {
    cwd: process.cwd(),
    env: process.env,
    stdio: 'inherit',
})

child.on('exit', code => {
    process.exit(code ?? 0)
})
