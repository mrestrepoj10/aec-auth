import { runChecks } from '../../../lib/checks'
import { isDiagnosticsAuthorized } from '../../../lib/diagnostics-auth'

export const dynamic = 'force-dynamic'

/** The canonical route-handler shape, returning the backend matrix as JSON. */
export async function GET(request: Request) {
  if (!(await isDiagnosticsAuthorized(request))) {
    return Response.json(
      { ok: false, error: 'unauthorized' },
      {
        status: 401,
        headers: {
          'Cache-Control': 'no-store',
          'WWW-Authenticate': 'Bearer',
        },
      },
    )
  }
  const checks = await runChecks()
  const failed = checks.some((check) => check.status === 'fail')
  return Response.json(
    { ok: !failed, checks },
    { status: failed ? 500 : 200, headers: { 'Cache-Control': 'private, no-store' } },
  )
}
