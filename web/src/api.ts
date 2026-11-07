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
export type TLSMode = 'auto' | 'dns' | 'internal' | 'off'

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
  folder_id: number | null
  policy_ids: number[]
  dns_provider_id: number | null
  request_headers: HeaderRule[]
  response_headers: HeaderRule[]
  health_check_path: string
  health_check_interval: number
  advanced_json: string
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

export type HeaderRule = {
  op: 'set' | 'add' | 'delete'
  name: string
  value: string
}

export type Folder = {
  id: number
  name: string
  parent_id: number | null
  sort: number
  policy_ids: number[]
  host_count: number
  dns_provider_id: number | null
  request_headers: HeaderRule[]
  response_headers: HeaderRule[]
}

export type DNSProvider = {
  id: number
  name: string
  type: 'cloudflare'
  token_set: boolean
  host_count: number
  folder_count: number
  created_at: string
}

export type TokenCheck = {
  active: boolean
  status: string
  zones: string[]
  zones_error?: string
}

/** The nearest folder default DNS provider (mirrors the server). */
export function folderDNSProvider(
  folderId: number | null,
  folders: Folder[],
): number | null {
  const byId = new Map(folders.map((f) => [f.id, f]))
  const seen = new Set<number>()
  for (let id = folderId; id != null && !seen.has(id);) {
    seen.add(id)
    const f = byId.get(id)
    if (!f) break
    if (f.dns_provider_id != null) return f.dns_provider_id
    id = f.parent_id
  }
  return null
}

export type AccessPolicy = {
  id: number
  name: string
  mode: 'allow_only' | 'deny'
  response: '403' | 'abort'
  rules: string[]
  notes: string
  folder_count: number
  host_count: number
}

export type NeverBan = { cidr: string; note: string; created_at: string }

/** A policy that applies to a host, and the folder it came from (null: the host itself). */
export type EffectivePolicy = { policy: AccessPolicy; from: Folder | null }

/** Mirrors store.AccessState.EffectivePolicies on the server. */
export function effectivePolicies(
  host: Pick<Host, 'folder_id' | 'policy_ids'>,
  folders: Folder[],
  policies: AccessPolicy[],
): EffectivePolicy[] {
  const byId = new Map(policies.map((p) => [p.id, p]))
  const folderById = new Map(folders.map((f) => [f.id, f]))
  const out: EffectivePolicy[] = []
  const seen = new Set<number>()
  const add = (ids: number[], from: Folder | null) => {
    for (const id of ids) {
      const p = byId.get(id)
      if (p && !seen.has(id)) {
        seen.add(id)
        out.push({ policy: p, from })
      }
    }
  }
  add(host.policy_ids, null)
  const visited = new Set<number>()
  for (let fid = host.folder_id; fid != null && !visited.has(fid);) {
    visited.add(fid)
    const f = folderById.get(fid)
    if (!f) break
    add(f.policy_ids, f)
    fid = f.parent_id
  }
  return out
}

/** Folders in tree order with their depth, for indented lists and selects. */
export function folderTree(
  folders: Folder[],
): { folder: Folder; depth: number }[] {
  const children = new Map<number | null, Folder[]>()
  for (const f of folders) {
    const k = f.parent_id ?? null
    children.set(k, [...(children.get(k) ?? []), f])
  }
  const out: { folder: Folder; depth: number }[] = []
  const walk = (parent: number | null, depth: number) => {
    for (const f of children.get(parent) ?? []) {
      out.push({ folder: f, depth })
      walk(f.id, depth + 1)
    }
  }
  walk(null, 0)
  return out
}

/** IDs of a folder and every folder below it. */
export function folderAndBelow(id: number, folders: Folder[]): Set<number> {
  const out = new Set([id])
  let grew = true
  while (grew) {
    grew = false
    for (const f of folders) {
      if (f.parent_id != null && out.has(f.parent_id) && !out.has(f.id)) {
        out.add(f.id)
        grew = true
      }
    }
  }
  return out
}

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
    // Session gone (expired, signed out elsewhere, database reset): let the
    // app return to the sign-in screen instead of showing errors on pages.
    if (
      res.status === 401 &&
      err.error === 'not_signed_in' &&
      path !== '/api/auth/me'
    )
      window.dispatchEvent(new Event('cpm:signed-out'))
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

  folders: () => request<Folder[]>('GET', '/api/folders'),
  saveFolder: (
    f: Pick<
      Folder,
      | 'id'
      | 'name'
      | 'parent_id'
      | 'policy_ids'
      | 'dns_provider_id'
      | 'request_headers'
      | 'response_headers'
    >,
  ) =>
    f.id
      ? request<Folder>('PUT', `/api/folders/${f.id}`, f)
      : request<Folder>('POST', '/api/folders', f),
  deleteFolder: (id: number) => request<void>('DELETE', `/api/folders/${id}`),
  setFolderEnabled: (id: number, enabled: boolean) =>
    request<{ hosts_changed: number }>('POST', `/api/folders/${id}/enabled`, {
      enabled,
    }),
  moveHost: (id: number, folder_id: number | null) =>
    request<Host>('POST', `/api/hosts/${id}/move`, { folder_id }),

  policies: () => request<AccessPolicy[]>('GET', '/api/policies'),
  savePolicy: (
    p: Pick<
      AccessPolicy,
      'id' | 'name' | 'mode' | 'response' | 'rules' | 'notes'
    >,
  ) =>
    p.id
      ? request<AccessPolicy>('PUT', `/api/policies/${p.id}`, p)
      : request<AccessPolicy>('POST', '/api/policies', p),
  deletePolicy: (id: number) => request<void>('DELETE', `/api/policies/${id}`),

  neverBan: () => request<NeverBan[]>('GET', '/api/never-ban'),
  addNeverBan: (cidr: string, note: string) =>
    request<NeverBan>('POST', '/api/never-ban', { cidr, note }),
  deleteNeverBan: (cidr: string) =>
    request<void>('DELETE', `/api/never-ban?cidr=${encodeURIComponent(cidr)}`),
  whoami: () => request<{ ip: string }>('GET', '/api/whoami'),

  dnsProviders: () =>
    request<{ providers: DNSProvider[]; secrets_ready: boolean }>(
      'GET',
      '/api/dns-providers',
    ),
  saveDNSProvider: (id: number, name: string, api_token: string) =>
    id
      ? request<DNSProvider>('PUT', `/api/dns-providers/${id}`, {
          name,
          type: 'cloudflare',
          api_token,
        })
      : request<DNSProvider>('POST', '/api/dns-providers', {
          name,
          type: 'cloudflare',
          api_token,
        }),
  deleteDNSProvider: (id: number) =>
    request<void>('DELETE', `/api/dns-providers/${id}`),
  verifyDNSProvider: (id: number) =>
    request<TokenCheck>('POST', `/api/dns-providers/${id}/verify`),
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
    folder_id: null,
    policy_ids: [],
    dns_provider_id: null,
    request_headers: [],
    response_headers: [],
    health_check_path: '',
    health_check_interval: 30,
    advanced_json: '',
  }
}
