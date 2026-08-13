import { runChecks } from '../../../lib/checks'

export const dynamic = 'force-dynamic'

/** The canonical route-handler shape, returning the backend matrix as JSON. */
export async function GET() {
  const checks = await runChecks()
  const failed = checks.some((check) => check.status === 'fail')
  return Response.json({ ok: !failed, checks }, { status: failed ? 500 : 200 })
}
