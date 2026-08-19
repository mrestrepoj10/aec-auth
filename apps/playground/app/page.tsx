export default function Page() {
  return (
    <main>
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>aec-auth playground</h1>
      <p style={{ color: '#454b51', lineHeight: 1.6 }}>
        Live provider diagnostics are not run from this public page. Use the protected{' '}
        <code>/api/token</code> endpoint with an <code>Authorization: Bearer</code> header matching{' '}
        <code>PLAYGROUND_DIAGNOSTICS_TOKEN</code>.
      </p>
      <p style={{ color: '#6a7076', fontSize: 13 }}>
        Detailed results can include upstream integration errors, so keep the diagnostics token
        private and call the endpoint only from trusted administrative tooling.
      </p>
    </main>
  )
}
