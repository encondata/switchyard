export type User = {
  id: number
  username: string
  role: 'admin' | 'editor' | 'viewer'
  must_change_password: boolean
}

export type Status = {
  version: string
  caddy: { reachable: boolean; socket?: string; error?: string }
}

export type HostType = 'proxy' | 'redirect' | '404'
export type TLSMode = 'auto' | 'internal' | 'off'

export type Upstream = {
  scheme: 'http' | 'https'
  host: string
  port: number
  skip_tls_verify: boolean
}

export type Host = {
  id: number
  type: HostType
  domains: string[]
  enabled: boolean
  upstreams: Upstream[]
  load_balancing: 'round_robin' | 'first'
  tls_mode: TLSMode
  force_https: boolean
  hsts: boolean
  compression: boolean
  redirect_to: string
  redirect_code: number
  preserve_path: boolean
  notes: string
  created_at?: string
  updated_at?: string
}

export type CertState =
  'valid' | 'expiring' | 'expired' | 'pending' | 'not_needed'

export type CertStatus = {
  domain: string
  state: CertState
  issuer?: string
  source?: string
  not_after?: string
}

export type HostView = Host & { certs: CertStatus[] }

export type ConfigVersion = {
  n: number
  json?: string
  sha256: string
  applied_by: string
  applied_at: string
  result: 'ok' | 'failed'
  error?: string
  note?: string
}

export type Preview = {
  pending: boolean
  diff: string
  drift: boolean
  caddy_error?: string
  last_applied?: ConfigVersion
  candidate_sha256: string
}

export class ApiError extends Error {
  status: number
  code: string
  fields: Record<string, string>

  constructor(
    status: number,
    code: string,
    message: string,
    fields: Record<string, string> = {},
  ) {
    super(message)
    this.status = status
    this.code = code
    this.fields = fields
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers:
      body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 204) return undefined as T
  const data: unknown = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = data as {
      error?: string
      message?: string
      fields?: Record<string, string>
    }
    throw new ApiError(
      res.status,
      err.error ?? 'error',
      err.message ?? `HTTP ${res.status}`,
      err.fields,
    )
  }
  return data as T
}

export const api = {
  me: () => request<User>('GET', '/api/auth/me'),
  login: (username: string, password: string) =>
    request<User>('POST', '/api/auth/login', { username, password }),
  logout: () => request<void>('POST', '/api/auth/logout'),
  changePassword: (current_password: string, new_password: string) =>
    request<User>('POST', '/api/auth/password', {
      current_password,
      new_password,
    }),
  status: () => request<Status>('GET', '/api/status'),

  hosts: () => request<HostView[]>('GET', '/api/hosts'),
  host: (id: number) => request<Host>('GET', `/api/hosts/${id}`),
  saveHost: (h: Host) =>
    h.id
      ? request<Host>('PUT', `/api/hosts/${h.id}`, h)
      : request<Host>('POST', '/api/hosts', h),
  deleteHost: (id: number) => request<void>('DELETE', `/api/hosts/${id}`),

  preview: () => request<Preview>('GET', '/api/config/preview'),
  apply: (note: string) =>
    request<ConfigVersion>('POST', '/api/config/apply', { note }),
  versions: () => request<ConfigVersion[]>('GET', '/api/config/versions'),
  version: (n: number) =>
    request<ConfigVersion>('GET', `/api/config/versions/${n}`),
  rollback: (n: number) =>
    request<ConfigVersion>('POST', `/api/config/versions/${n}/rollback`),
}

export function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export function newHost(): Host {
  return {
    id: 0,
    type: 'proxy',
    domains: [],
    enabled: true,
    upstreams: [{ scheme: 'http', host: '', port: 80, skip_tls_verify: false }],
    load_balancing: 'round_robin',
    tls_mode: 'auto',
    force_https: true,
    hsts: false,
    compression: true,
    redirect_to: '',
    redirect_code: 301,
    preserve_path: true,
    notes: '',
  }
}
