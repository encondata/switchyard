/** One user's display preferences. accent '' = the default teal. */
export type Prefs = { accent: string }

export type User = {
  id: number
  username: string
  role: 'admin' | 'editor' | 'viewer'
  must_change_password: boolean
  disabled: boolean
  totp_enabled: boolean
  must_enroll_2fa: boolean
  created_at?: string
}

export type LoginResult = User | { totp_required: true; challenge: string }

export type TwoFAStatus = {
  enabled: boolean
  required: boolean
  backup_codes_left: number
  available: boolean
}

export type AuditEntry = {
  id: number
  at: string
  username: string
  action: string
  entity: string
  entity_id: string
  before: string
  after: string
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
  trap_exceptions: string[]
  rate_limit_events: number
  rate_limit_window: number
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
  rate_limit_events: number
  rate_limit_window: number
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
  changes: number
}

export type Alert = {
  id: number
  kind: string
  subject: string
  message: string
  created_at: string
  last_seen_at: string
  resolved_at?: string
}

export type CertRow = {
  domain: string
  host_id: number
  tls_mode: TLSMode
  state: CertState
  issuer?: string
  not_after?: string
  last_error?: { message: string; at: string }
}

export type Country = { code: string; name: string }

export type Health = {
  version: string
  monitor: {
    checked_at: string
    caddy_reachable: boolean
    caddy_error?: string
    drift: boolean
    last_apply?: ConfigVersion
    log_bytes: number
  }
  alerts: Alert[]
  db_bytes: number
  secrets_ready: boolean
  geoip: {
    installed: boolean
    updated_at?: string
    age_days?: number
    source?: 'DB-IP' | 'MaxMind' | ''
  }
}

export type ImportPlan = {
  hosts: {
    source: string
    host: Host
    policies: string[]
    warnings: string[]
    skip?: string
  }[]
  policies: { source: string; policy: AccessPolicy }[]
  streams: {
    id: number
    incoming_port: number
    forward: string
    protocols: string
    enabled: boolean
  }[]
  warnings: string[]
}

export type ImportResult = {
  folder_id: number
  hosts_created: number
  policies_created: number
  skipped: string[]
}

/** A running NPM's admin address and login (used once, not stored). */
export type NPMConnection = {
  url: string
  email: string
  password: string
  insecure_tls: boolean
}

export type MySQLConfig = {
  host: string
  port: number
  user: string
  password: string
  database: string
}

export type StatsPoint = {
  t: string
  requests: number
  bytes: number
  errors: number
  blocked: number
}

export type StatsOverview = {
  overview: {
    series: StatsPoint[]
    requests: number
    bytes: number
    errors: number
    blocked: number
    bucket: number
  }
  latency: { p50_ms: number; p95_ms: number; samples: number }
}

export type TopRow = {
  key: string
  count: number
  blocked: number
  country?: string
}

export type HitRow = {
  id: number
  ts: string
  host: string
  client_ip: string
  country: string
  method: string
  path: string
  status: number
  bytes: number
  duration_ms: number
  user_agent: string
  matched: 'allowed' | 'blocked' | 'honeypot'
  reason: string
  reason_text?: string
}

export type IPDetail = {
  ip: string
  country: string
  total: number
  blocked: number
  hosts: TopRow[]
  recent: HitRow[]
  never_ban: boolean
  banned?: boolean
}

export type StatsScope = { range: string; host?: number; folder?: number }

/** An API key (the token itself is only ever in createAPIKey's answer). */
export type APIKey = {
  id: number
  name: string
  prefix: string
  permissions: string[]
  created_by: string
  created_at: string
  updated_at: string
  expires_at: string | null
  last_used_at: string | null
  last_used_ip: string
  revoked_at: string | null
}

/** An API operation a key can be given. */
export type APIOperation = {
  id: string
  method: string
  path: string
  area: string
  summary: string
  role: string
  keyable: boolean
  write: boolean
  query?: { name: string; description: string }[]
}

export type APIKeyInput = {
  name: string
  permissions: string[]
  expires_at: string | null
}

/** One country's traffic: totals, when, and which hosts, paths and IPs. */
export type CountryDetail = {
  country: string
  series: StatsPoint[]
  bucket: number
  requests: number
  bytes: number
  errors: number
  blocked: number
  unique_ips: number
  hosts: TopRow[]
  paths: TopRow[]
  ips: TopRow[]
  status: TopRow[]
  recent: HitRow[]
}

function scopeQuery(s: StatsScope, extra: Record<string, string> = {}) {
  const p = new URLSearchParams({ range: s.range, ...extra })
  if (s.host) p.set('host', String(s.host))
  if (s.folder) p.set('folder', String(s.folder))
  return p.toString()
}

export type HoneypotSettings = {
  enabled: boolean
  response: 'login' | 'server' | 'empty' | '404'
  catchall_score: number
  threshold: number
  window_hours: number
  ban_days: number
  max_ban_days: number
}

export type TrapPath = {
  id: number
  pattern: string
  score: number
  enabled: boolean
}

export type Ban = {
  id: number
  cidr: string
  reason: string
  source: 'honeypot' | 'manual' | 'crowdsec'
  created_by: string
  created_at: string
  expires_at: string | null
  removed_at?: string
  hit_count: number
  active: boolean
}

export type HoneypotActivity = {
  path: TopRow[]
  ip: TopRow[]
  ua: TopRow[]
  host: TopRow[]
  recent: HitRow[]
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
  preferences: () => request<Prefs>('GET', '/api/auth/preferences'),
  savePreferences: (p: Prefs) =>
    request<Prefs>('PUT', '/api/auth/preferences', p),
  login: (username: string, password: string) =>
    request<LoginResult>('POST', '/api/auth/login', { username, password }),
  loginTOTP: (challenge: string, code: string) =>
    request<User>('POST', '/api/auth/totp', { challenge, code }),
  twoFA: () => request<TwoFAStatus>('GET', '/api/auth/2fa'),
  twoFABegin: () =>
    request<{ secret: string; uri: string }>('POST', '/api/auth/2fa/begin'),
  twoFAConfirm: (code: string) =>
    request<{ backup_codes: string[] }>('POST', '/api/auth/2fa/confirm', {
      code,
    }),
  twoFADisable: (password: string) =>
    request<void>('POST', '/api/auth/2fa/disable', { password }),
  users: () => request<User[]>('GET', '/api/users'),
  createUser: (username: string, role: User['role'], password: string) =>
    request<User>('POST', '/api/users', { username, role, password }),
  updateUser: (id: number, role: User['role'], disabled: boolean) =>
    request<User>('PUT', `/api/users/${id}`, { role, disabled }),
  resetUserPassword: (id: number, password: string) =>
    request<void>('POST', `/api/users/${id}/password`, { password }),
  resetUser2FA: (id: number) =>
    request<void>('POST', `/api/users/${id}/reset-2fa`),
  deleteUser: (id: number) => request<void>('DELETE', `/api/users/${id}`),
  settings: () =>
    request<{ require_2fa: boolean; secrets_ready: boolean }>(
      'GET',
      '/api/settings',
    ),
  saveSettings: (require_2fa: boolean) =>
    request<{ require_2fa: boolean }>('PUT', '/api/settings', { require_2fa }),
  audit: (q: { before?: number; entity?: string; user?: string }) => {
    const p = new URLSearchParams()
    if (q.before) p.set('before', String(q.before))
    if (q.entity) p.set('entity', q.entity)
    if (q.user) p.set('user', q.user)
    return request<AuditEntry[]>('GET', `/api/audit?${p.toString()}`)
  },
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
  versionDiff: (n: number) =>
    request<{ diff: string; previous: number }>(
      'GET',
      `/api/config/versions/${n}/diff`,
    ),
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
      | 'rate_limit_events'
      | 'rate_limit_window'
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
  countries: () => request<Country[]>('GET', '/api/countries'),
  statsOverview: (s: StatsScope) =>
    request<StatsOverview>('GET', `/api/stats/overview?${scopeQuery(s)}`),
  statsTop: (s: StatsScope, dim: string, limit = 10) =>
    request<TopRow[]>(
      'GET',
      `/api/stats/top?${scopeQuery(s, { dim, limit: String(limit) })}`,
    ),
  statsTail: (s: StatsScope, after: number) =>
    request<HitRow[]>(
      'GET',
      `/api/stats/tail?${scopeQuery(s, { after: String(after) })}`,
    ),
  honeypot: () =>
    request<{ settings: HoneypotSettings; traps: TrapPath[] }>(
      'GET',
      '/api/honeypot',
    ),
  saveHoneypot: (h: HoneypotSettings) =>
    request<HoneypotSettings>('PUT', '/api/honeypot', h),
  saveTrap: (t: TrapPath) =>
    t.id
      ? request<TrapPath>('PUT', `/api/honeypot/traps/${t.id}`, t)
      : request<TrapPath>('POST', '/api/honeypot/traps', t),
  deleteTrap: (id: number) =>
    request<void>('DELETE', `/api/honeypot/traps/${id}`),
  honeypotActivity: (range: string) =>
    request<HoneypotActivity>('GET', `/api/honeypot/activity?range=${range}`),
  bans: (all: boolean) =>
    request<Ban[]>('GET', `/api/bans${all ? '?all=1' : ''}`),
  addBan: (cidr: string, reason: string, days: number) =>
    request<{ ban: Ban; warning: string }>('POST', '/api/bans', {
      cidr,
      reason,
      days,
    }),
  removeBan: (id: number) =>
    request<{ warning: string }>('DELETE', `/api/bans/${id}`),
  unbanAddress: (cidr: string) =>
    request<{ lifted: number; warning: string }>('POST', '/api/bans/unban', {
      cidr,
    }),
  crowdsec: () =>
    request<{ enabled: boolean; api_url: string; key_set: boolean }>(
      'GET',
      '/api/crowdsec',
    ),
  saveCrowdSec: (enabled: boolean, api_url: string, api_key: string) =>
    request<{ enabled: boolean; api_url: string; key_set: boolean }>(
      'PUT',
      '/api/crowdsec',
      { enabled, api_url, api_key },
    ),
  apiKeys: () => request<APIKey[]>('GET', '/api/keys'),
  keyOperations: () => request<APIOperation[]>('GET', '/api/keys/operations'),
  createAPIKey: (k: APIKeyInput) =>
    request<{ key: APIKey; token: string }>('POST', '/api/keys', k),
  updateAPIKey: (id: number, k: APIKeyInput) =>
    request<APIKey>('PUT', `/api/keys/${id}`, k),
  revokeAPIKey: (id: number) => request<void>('POST', `/api/keys/${id}/revoke`),
  openapi: () => request<OpenAPIDoc>('GET', '/api/openapi.json'),
  /** code: ISO country, 'LAN', or 'unknown'. */
  statsCountry: (s: StatsScope, code: string) =>
    request<CountryDetail>(
      'GET',
      `/api/stats/country/${encodeURIComponent(code || 'unknown')}?${scopeQuery(s)}`,
    ),
  statsIP: (ip: string) =>
    request<IPDetail>('GET', `/api/stats/ip/${encodeURIComponent(ip)}`),

  /** Open alerts, or with all=true also recently resolved ones. */
  alerts: (all = false) =>
    request<Alert[]>('GET', all ? '/api/alerts?all=1' : '/api/alerts'),
  health: () => request<Health>('GET', '/api/health/details'),
  checkNow: () => request<Health>('POST', '/api/health/check'),
  certificates: () => request<CertRow[]>('GET', '/api/certificates'),
  retryCerts: () => request<void>('POST', '/api/certificates/retry'),
  importPreviewFile: async (file: File) => {
    const res = await fetch('/api/import/npm/preview', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/vnd.sqlite3' },
      body: file,
    })
    const data = (await res.json().catch(() => ({}))) as {
      plan_id?: string
      plan?: ImportPlan
      error?: string
      message?: string
    }
    if (!res.ok)
      throw new ApiError(
        res.status,
        data.error ?? 'error',
        data.message ?? `HTTP ${res.status}`,
      )
    return data as { plan_id: string; plan: ImportPlan }
  },
  importPreviewAPI: (api: NPMConnection) =>
    request<{ plan_id: string; plan: ImportPlan }>(
      'POST',
      '/api/import/npm/preview',
      { api },
    ),
  importPreviewMySQL: (mysql: MySQLConfig) =>
    request<{ plan_id: string; plan: ImportPlan }>(
      'POST',
      '/api/import/npm/preview',
      { mysql },
    ),
  importRun: (plan_id: string) =>
    request<ImportResult>('POST', '/api/import/npm/run', { plan_id }),
  restore: async (file: File) => {
    const res = await fetch('/api/restore', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/vnd.sqlite3' },
      body: file,
    })
    const data = (await res.json().catch(() => ({}))) as {
      message?: string
      error?: string
    }
    if (!res.ok)
      throw new ApiError(
        res.status,
        data.error ?? 'error',
        data.message ?? `HTTP ${res.status}`,
      )
    return data.message ?? 'Restoring…'
  },

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
    trap_exceptions: [],
    rate_limit_events: 0,
    rate_limit_window: 60,
  }
}

/** The parts of the OpenAPI document the API reference page shows. */
export type OpenAPIDoc = {
  info: { title: string; version: string; description: string }
  tags: { name: string }[]
  paths: Record<
    string,
    Record<
      string,
      {
        operationId: string
        summary: string
        description: string
        tags: string[]
        parameters: { name: string; in: string; description?: string }[]
        requestBody?: { content: { 'application/json': { schema: unknown } } }
        'x-keyable': boolean
        'x-writes': boolean
      }
    >
  >
  components: { schemas: Record<string, unknown> }
}
