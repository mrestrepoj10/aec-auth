import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/aps.ts',
    'src/vault.ts',
    'src/vault-upstash.ts',
    'src/connect.ts',
    'src/betterauth.ts',
    'src/mock.ts',
    'src/webhooks.ts',
    'src/ssa.ts',
  ],
  format: ['esm'],
  dts: true,
  clean: true,
})
