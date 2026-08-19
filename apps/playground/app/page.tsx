import { type Check, runChecks } from '../lib/checks'

const COLORS = { pass: '#237a3f', skipped: '#6a7076', fail: '#b3261e' } as const
const LABELS = { pass: 'PASS', skipped: 'SKIP', fail: 'FAIL' } as const

function Matrix({ checks }: { checks: Check[] }) {
  return (
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
  )
}

export default async function Page() {
  // The live matrix renders only on the local dev server. Production builds
  // stay static and passive: detailed diagnostics can mint tokens and expose
  // provider errors, so deployed instances serve them solely through the
  // authenticated /api/token route.
  const development = process.env.NODE_ENV === 'development'
  const checks = development ? await runChecks() : undefined

  return (
    <main>
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>aec-auth playground</h1>
      {checks ? (
        <>
          <p style={{ color: '#6a7076', marginTop: 0 }}>
            Development mode — every TokenSource backend, exercised server-side on each request.
            Skipped rows list the env they need.
          </p>
          <Matrix checks={checks} />
          <p style={{ color: '#6a7076', fontSize: 13, marginTop: 24 }}>
            JSON at <code>/api/token</code> (no token needed in development). Full flows live in the
            test suite: <code>pnpm vitest run test/aps.emulator.test.ts</code>.
          </p>
        </>
      ) : (
        <>
          <p style={{ color: '#454b51', lineHeight: 1.6 }}>
            Live provider diagnostics are not run from this public page. Use the protected{' '}
            <code>/api/token</code> endpoint with an <code>Authorization: Bearer</code> header
            matching <code>PLAYGROUND_DIAGNOSTICS_TOKEN</code>, or run the playground locally with{' '}
            <code>pnpm dev</code> to see the live matrix.
          </p>
          <p style={{ color: '#6a7076', fontSize: 13 }}>
            Detailed results can include upstream integration errors, so keep the diagnostics token
            private and call the endpoint only from trusted administrative tooling.
          </p>
        </>
      )}
    </main>
  )
}
