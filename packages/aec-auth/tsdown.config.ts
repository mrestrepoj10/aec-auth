import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/aps.ts',
    'src/procore.ts',
    'src/vault.ts',
    'src/vault-upstash.ts',
    'src/connect.ts',
    'src/authjs.ts',
    'src/betterauth.ts',
    'src/mock.ts',
  ],
  format: ['esm'],
  dts: true,
  clean: true,
})
