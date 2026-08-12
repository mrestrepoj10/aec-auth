/**
 * Typed Procore REST v1.0 client (`aec-auth/procore`). Wraps a
 * {@link TokenSource}: every request resolves a token, spreads the
 * `Authorization` header, and retries exactly once with a force-refreshed
 * token when the API answers 401. Company-scoped endpoints send the
 * `Procore-Company-Id` header Procore requires for multi-company accounts.
 */
import {
  authHeaders,
  PROCORE_BASE_URL,
  PROCORE_SANDBOX_BASE_URL,
  type TokenSource,
  type TokenSubject,
} from './index'

/** A company as returned by `GET /rest/v1.0/companies`. */
export interface ProcoreCompany {
  id: number
  name: string
  is_active?: boolean
  [key: string]: unknown
}

/** A project as returned by `GET /rest/v1.0/projects`. */
export interface ProcoreProject {
  id: number
  name: string
  company?: { id: number; name?: string }
  [key: string]: unknown
}

/** The authenticated user as returned by `GET /rest/v1.0/me`. */
export interface ProcoreUser {
  id: number
  login: string
  name?: string
  [key: string]: unknown
}

export interface ProcoreClientOptions {
  /** Where tokens come from (`aec-auth/connect`, `aec-auth/vault`, a mock, …). */
  tokens: TokenSource
  /** Who the requests act as (app or a specific user). */
  subject: TokenSubject
  /** Default company for company-scoped endpoints; overridable per call. */
  companyId?: number
  /** Use the Procore sandbox environment. Ignored when `baseUrl` is set. */
  sandbox?: boolean
  /** Override the API origin. Defaults per `sandbox`. */
  baseUrl?: string
  /** Injectable `fetch` for tests and mocks. Defaults to the global. */
  fetch?: typeof fetch
}

/** The client returned by {@link createProcoreClient}. */
export interface ProcoreClient {
  companies: {
    /** `GET /rest/v1.0/companies` — companies the subject can access. */
    list(): Promise<ProcoreCompany[]>
  }
  projects: {
    /**
     * `GET /rest/v1.0/projects?company_id=…` with `Procore-Company-Id`.
     * `companyId` overrides the client-level default; one of the two is
     * required.
     */
    list(companyId?: number): Promise<ProcoreProject[]>
  }
  /** `GET /rest/v1.0/me` — the authenticated user. */
  me(): Promise<ProcoreUser>
  /**
   * Escape hatch: any Procore path, authenticated the same way, parsed as
   * JSON. Sends `Procore-Company-Id` from the client's `companyId` unless the
   * caller already set that header.
   */
  request<T = unknown>(path: string, init?: RequestInit): Promise<T>
}

/**
 * Creates a typed Procore REST client on top of a {@link TokenSource}.
 */
export function createProcoreClient(options: ProcoreClientOptions): ProcoreClient {
  const baseUrl = options.baseUrl ?? (options.sandbox ? PROCORE_SANDBOX_BASE_URL : PROCORE_BASE_URL)
  // Bind the global so a detached `window.fetch` never throws Illegal invocation.
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis)

  async function send(path: string, init: RequestInit | undefined, forceRefresh: boolean) {
    const token = await options.tokens.getToken({
      provider: 'procore',
      subject: options.subject,
      ...(forceRefresh ? { forceRefresh: true } : {}),
    })
    const headers = new Headers(init?.headers)
    headers.set('Authorization', authHeaders(token).Authorization)
    if (!headers.has('Procore-Company-Id') && options.companyId !== undefined) {
      headers.set('Procore-Company-Id', String(options.companyId))
    }
    return fetchImpl(`${baseUrl}${path}`, { ...init, headers })
  }

  async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    let response = await send(path, init, false)
    // A 401 usually means a stale cached token — refresh once, then give up.
    if (response.status === 401) response = await send(path, init, true)
    if (!response.ok) {
      const body = await response.text().catch(() => '')
      throw new Error(
        `Procore request ${path} failed with ${response.status} ${response.statusText}` +
          (body ? `: ${body}` : ''),
      )
    }
    return (await response.json()) as T
  }

  return {
    companies: {
      list: () => requestJson<ProcoreCompany[]>('/rest/v1.0/companies'),
    },
    projects: {
      list: async (companyId) => {
        const id = companyId ?? options.companyId
        if (id === undefined) {
          throw new Error(
            'Procore projects.list needs a company id: pass projects.list(companyId) or set ' +
              'companyId on createProcoreClient.',
          )
        }
        return requestJson<ProcoreProject[]>(`/rest/v1.0/projects?company_id=${id}`, {
          headers: { 'Procore-Company-Id': String(id) },
        })
      },
    },
    me: () => requestJson<ProcoreUser>('/rest/v1.0/me'),
    request: (path, init) => requestJson(path, init),
  }
}
