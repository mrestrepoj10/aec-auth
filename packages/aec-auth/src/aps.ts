/**
 * Typed Autodesk Platform Services client for the Data Management API
 * (`aec-auth/aps`). Wraps a {@link TokenSource} so callers never touch raw
 * tokens: every request resolves a token (scope `data:read`), spreads the
 * `Authorization` header, and retries exactly once with a force-refreshed
 * token when the API answers 401.
 */
import { APS_BASE_URL, apsScopes, authHeaders, type TokenSource, type TokenSubject } from './index'

/** A JSON:API resource object as returned by the APS Data Management API. */
export interface JsonApiItem {
  id: string
  type: string
  attributes: { name?: string } & Record<string, unknown>
}

/** JSON:API list envelope (`GET .../hubs`, `GET .../hubs/:id/projects`). */
export interface JsonApiList {
  data: JsonApiItem[]
}

/** JSON:API single-resource envelope (`GET .../hubs/:id`). */
export interface JsonApiOne {
  data: JsonApiItem
}

export interface ApsClientOptions {
  /** Where tokens come from (`aec-auth/connect`, `aec-auth/vault`, a mock, …). */
  tokens: TokenSource
  /** Who the requests act as (app or a specific user). */
  subject: TokenSubject
  /** Override the API origin. Defaults to {@link APS_BASE_URL}. */
  baseUrl?: string
  /** Injectable `fetch` for tests and mocks. Defaults to the global. */
  fetch?: typeof fetch
}

/** The client returned by {@link createApsClient}. */
export interface ApsClient {
  hubs: {
    /** `GET /project/v1/hubs` — all hubs the subject can see. */
    list(): Promise<JsonApiList>
    /** `GET /project/v1/hubs/:hubId` — one hub. */
    get(hubId: string): Promise<JsonApiOne>
  }
  projects: {
    /** `GET /project/v1/hubs/:hubId/projects` — projects in a hub. */
    list(hubId: string): Promise<JsonApiList>
    /** `GET /project/v1/hubs/:hubId/projects/:projectId` — one project. */
    get(hubId: string, projectId: string): Promise<JsonApiOne>
  }
  /** Escape hatch: any APS path, authenticated the same way, parsed as JSON. */
  request<T = unknown>(path: string, init?: RequestInit): Promise<T>
}

/**
 * Creates a typed APS Data Management client on top of a {@link TokenSource}.
 */
export function createApsClient(options: ApsClientOptions): ApsClient {
  const baseUrl = options.baseUrl ?? APS_BASE_URL
  // Bind the global so a detached `window.fetch` never throws Illegal invocation.
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis)

  async function send(path: string, init: RequestInit | undefined, forceRefresh: boolean) {
    const token = await options.tokens.getToken({
      provider: 'aps',
      subject: options.subject,
      scopes: apsScopes.dataRead,
      ...(forceRefresh ? { forceRefresh: true } : {}),
    })
    const headers = new Headers(init?.headers)
    headers.set('Authorization', authHeaders(token).Authorization)
    return fetchImpl(`${baseUrl}${path}`, { ...init, headers })
  }

  async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    let response = await send(path, init, false)
    // A 401 usually means a stale cached token — refresh once, then give up.
    if (response.status === 401) response = await send(path, init, true)
    if (!response.ok) {
      const body = await response.text().catch(() => '')
      throw new Error(
        `APS request ${path} failed with ${response.status} ${response.statusText}` +
          (body ? `: ${body}` : ''),
      )
    }
    return (await response.json()) as T
  }

  return {
    hubs: {
      list: () => requestJson<JsonApiList>('/project/v1/hubs'),
      get: (hubId) => requestJson<JsonApiOne>(`/project/v1/hubs/${encodeURIComponent(hubId)}`),
    },
    projects: {
      list: (hubId) =>
        requestJson<JsonApiList>(`/project/v1/hubs/${encodeURIComponent(hubId)}/projects`),
      get: (hubId, projectId) =>
        requestJson<JsonApiOne>(
          `/project/v1/hubs/${encodeURIComponent(hubId)}/projects/${encodeURIComponent(projectId)}`,
        ),
    },
    request: (path, init) => requestJson(path, init),
  }
}
