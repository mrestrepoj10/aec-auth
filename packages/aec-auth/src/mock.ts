/**
 * Zero-credential dev/test providers (`aec-auth/mock`): a deterministic
 * {@link TokenSource} plus `fetch` doubles that serve realistic APS / Procore
 * fixtures for exactly the routes the typed clients call. Requests without an
 * `Authorization` header get a 401, so auth wiring is actually exercised.
 */

import type { JsonApiItem } from './aps'
import { subjectKey, type TokenSource } from './index'
import type { ProcoreCompany, ProcoreProject, ProcoreUser } from './procore'

/**
 * Deterministic token source for dev and tests. Tokens look like
 * `mock-{provider}-{subjectKey}` (e.g. `mock-aps-app`, `mock-procore-user:u1`)
 * and get a fresh expiry on every call.
 */
export function mockTokenSource(options?: { ttlMs?: number }): TokenSource {
  const ttlMs = options?.ttlMs ?? 3_600_000
  return {
    async getToken(request) {
      return {
        token: `mock-${request.provider}-${subjectKey(request.subject)}`,
        expiresAt: Date.now() + ttlMs,
        ...(request.scopes ? { scopes: request.scopes } : {}),
      }
    },
  }
}

/** Fixture data served by {@link mockApsFetch}, JSON:API shaped. */
export const apsFixtures: {
  hubs: JsonApiItem[]
  /** Projects keyed by hub id. */
  projects: Record<string, JsonApiItem[]>
} = {
  hubs: [
    { id: 'b.mock-hub-1', type: 'hubs', attributes: { name: 'Mock Design Hub', region: 'US' } },
    {
      id: 'b.mock-hub-2',
      type: 'hubs',
      attributes: { name: 'Mock Construction Hub', region: 'EMEA' },
    },
  ],
  projects: {
    'b.mock-hub-1': [
      { id: 'b.mock-project-1', type: 'projects', attributes: { name: 'Tower Renovation' } },
      { id: 'b.mock-project-2', type: 'projects', attributes: { name: 'Bridge Retrofit' } },
      { id: 'b.mock-project-3', type: 'projects', attributes: { name: 'Airport Extension' } },
    ],
    'b.mock-hub-2': [
      { id: 'b.mock-project-4', type: 'projects', attributes: { name: 'Hospital West Wing' } },
      { id: 'b.mock-project-5', type: 'projects', attributes: { name: 'Data Center Fit-Out' } },
    ],
  },
}

/** Fixture data served by {@link mockProcoreFetch}. */
export const procoreFixtures: {
  companies: ProcoreCompany[]
  projects: ProcoreProject[]
  me: ProcoreUser
} = {
  companies: [
    { id: 1, name: 'Mock Constructors Inc', is_active: true },
    { id: 2, name: 'Mock Heavy Civil LLC', is_active: true },
  ],
  projects: [
    { id: 101, name: 'Riverside Tower', company: { id: 1, name: 'Mock Constructors Inc' } },
    { id: 102, name: 'Harbor Bridge Rehab', company: { id: 1, name: 'Mock Constructors Inc' } },
    { id: 201, name: 'Desert Solar Farm', company: { id: 2, name: 'Mock Heavy Civil LLC' } },
  ],
  me: { id: 42, login: 'dev@example.com', name: 'Mock Developer' },
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function unauthorized(): Response {
  return json({ error: 'unauthorized', message: 'Missing Authorization header' }, 401)
}

function notFound(path: string): Response {
  return json({ error: 'not_found', message: `No mock route for ${path}` }, 404)
}

/**
 * A `fetch` double for the APS Data Management routes the APS client calls:
 * hubs list/get and projects list/get under `/project/v1`. Unknown routes get
 * a 404; requests without an `Authorization` header get a 401.
 */
export function mockApsFetch(): typeof fetch {
  return async (input, init) => {
    const request = new Request(input, init)
    if (!request.headers.get('authorization')) return unauthorized()
    const { pathname } = new URL(request.url)
    const segments = pathname.split('/').filter(Boolean).map(decodeURIComponent)

    if (segments[0] !== 'project' || segments[1] !== 'v1' || segments[2] !== 'hubs') {
      return notFound(pathname)
    }
    if (segments.length === 3) return json({ data: apsFixtures.hubs })

    const hubId = segments[3]
    const hub = apsFixtures.hubs.find((candidate) => candidate.id === hubId)
    if (!hub || hubId === undefined) return notFound(pathname)
    if (segments.length === 4) return json({ data: hub })

    if (segments[4] !== 'projects') return notFound(pathname)
    const projects = apsFixtures.projects[hubId] ?? []
    if (segments.length === 5) return json({ data: projects })

    const project = projects.find((candidate) => candidate.id === segments[5])
    if (segments.length === 6 && project) return json({ data: project })
    return notFound(pathname)
  }
}

/**
 * A `fetch` double for the Procore routes the Procore client calls:
 * `/rest/v1.0/companies`, `/rest/v1.0/projects?company_id=…` (filtered by
 * company), and `/rest/v1.0/me`. Unknown routes get a 404; requests without
 * an `Authorization` header get a 401.
 */
export function mockProcoreFetch(): typeof fetch {
  return async (input, init) => {
    const request = new Request(input, init)
    if (!request.headers.get('authorization')) return unauthorized()
    const url = new URL(request.url)

    switch (url.pathname) {
      case '/rest/v1.0/companies':
        return json(procoreFixtures.companies)
      case '/rest/v1.0/projects': {
        const companyId = url.searchParams.get('company_id')
        const projects = companyId
          ? procoreFixtures.projects.filter((project) => project.company?.id === Number(companyId))
          : procoreFixtures.projects
        return json(projects)
      }
      case '/rest/v1.0/me':
        return json(procoreFixtures.me)
      default:
        return notFound(url.pathname)
    }
  }
}
