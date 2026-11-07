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

export class ApiError extends Error {
  status: number
  code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
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
    const err = data as { error?: string; message?: string }
    throw new ApiError(
      res.status,
      err.error ?? 'error',
      err.message ?? `HTTP ${res.status}`,
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
}
