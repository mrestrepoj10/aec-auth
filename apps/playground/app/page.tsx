import { runChecks } from '../lib/checks'

export const dynamic = 'force-dynamic'

const COLORS = { pass: '#237a3f', skipped: '#6a7076', fail: '#b3261e' } as const
const LABELS = { pass: 'PASS', skipped: 'SKIP', fail: 'FAIL' } as const

export default async function Page() {
  const checks = await runChecks()
  return (
    <main>
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>aec-auth playground</h1>
      <p style={{ color: '#6a7076', marginTop: 0 }}>
        Every TokenSource backend, exercised server-side on each request. Skipped rows list the env
        they need.
      </p>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
        <tbody>
          {checks.map((check) => (
            <tr key={check.name} style={{ borderTop: '1px solid #d6d7d0' }}>
              <td style={{ padding: '10px 8px 10px 0', fontWeight: 600, whiteSpace: 'nowrap' }}>
                {check.name}
                <div style={{ fontWeight: 400, color: '#6a7076', fontSize: 12 }}>{check.how}</div>
              </td>
              <td
                style={{
                  padding: '10px 8px',
                  color: COLORS[check.status],
                  fontFamily: 'ui-monospace, monospace',
                  fontWeight: 700,
                  fontSize: 12,
                  whiteSpace: 'nowrap',
                }}
              >
                {LABELS[check.status]}
              </td>
              <td style={{ padding: '10px 0', color: '#454b51' }}>{check.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p style={{ color: '#6a7076', fontSize: 13, marginTop: 24 }}>
        JSON version at <code>/api/token</code>. Full flows (3-legged consent, rotation, replay)
        live in the test suite: <code>pnpm vitest run test/aps.emulator.test.ts</code>.
      </p>
    </main>
  )
}
