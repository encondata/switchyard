# Switchyard API

Everything the web UI does goes through a JSON REST API under `/api/`, and
other programs can use it too: add hosts from a deploy script, ban addresses
from an intrusion detector, pull traffic numbers into a dashboard.

- **Machine-readable description:** `GET /api/openapi.json` (OpenAPI 3.1,
  public). Use it to generate a client or import into Postman or Insomnia.
- **In the app:** Administration → API keys → **API reference** lists every
  endpoint with the permission it needs.

## Authentication: API keys

An admin makes keys on **Administration → API keys**. Each key has:

- a **name** (say, the program that uses it), shown in the audit log as
  `api:<name>`;
- the **operations** it may call, chosen one by one (each endpoint has an
  operation ID such as `hosts.update`; see the table below);
- an optional **expiry date**.

The key (`sy_…`) is shown **once**, when it's made. Switchyard stores only a
SHA-256 fingerprint of it. If it's lost, revoke it and make a new one.

Send the key with every request, either way:

```bash
curl -H "Authorization: Bearer sy_…" https://switchyard.example.com/api/hosts
curl -H "X-API-Key: sy_…"            https://switchyard.example.com/api/hosts
```

- Editing a key's permissions takes effect on its next request; the token
  doesn't change.
- Revoking a key stops it at once. Expired and revoked keys answer `401`.
- Keys can't sign in, change passwords, manage API keys or restore a
  backup. Those stay with people.
- A key acts with exactly the role its operation needs. For example
  `hosts.create` is an editor operation, so a key can't set a host's
  admin-only advanced JSON through it.

Keep keys out of source control. Give each program its own key with only
what it needs, so you can see what each one did and revoke it on its own.

## Requests and answers

- Bodies are JSON, sent with `Content-Type: application/json`.
- Answers are JSON. Success is a `2xx` status; lists are arrays.
- `PUT` replaces the whole object: send every field, as `GET` returns it.
- Errors have this shape, with `fields` for validation problems:

```json
{ "error": "invalid", "message": "Fix the highlighted fields.", "fields": { "domains": "Add at least one domain." } }
```

| Status | Meaning | Typical `error` |
|---|---|---|
| 400 | The request isn't valid | `invalid`, `bad_request` |
| 401 | No key, or the key is wrong, revoked or expired | `invalid_api_key`, `not_signed_in` |
| 403 | The key lacks this operation, or keys can't use it | `missing_permission`, `not_for_api_keys` |
| 404 | No such thing | `not_found` |
| 409 | Conflicts with something else, e.g. a domain already used | `conflict` |
| 422 | Caddy rejected the config; it keeps running the previous one | `caddy_rejected` |

## Changes are staged, then applied

Creating, changing or deleting hosts, folders, access policies, never-block
entries and DNS providers only changes Switchyard's database. Caddy keeps
serving the old config until something calls **`POST /api/config/apply`**
(`config.apply`), just like **Review & apply** in the UI. Each apply becomes
a numbered version you can diff and roll back to.

- `GET /api/config/preview` (`config.preview`) shows what an apply would
  change.
- Bans and the honeypot don't need an apply: they reach Caddy within
  seconds.

## Examples

Set `KEY` and `SY` first:

```bash
KEY=sy_…
SY=https://switchyard.example.com
```

**Add a host and put it live** (`hosts.create`, `config.apply`):

```bash
curl -X POST $SY/api/hosts -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -d '{
  "type": "proxy", "enabled": true,
  "domains": ["app.example.com"],
  "tls_mode": "auto", "force_https": true,
  "upstreams": [{"scheme": "http", "host": "10.0.0.5", "port": 8080}]
}'
curl -X POST $SY/api/config/apply -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"note": "app.example.com from deploy script"}'
```

**Change a host** (`hosts.get`, `hosts.update`): fetch it, change fields,
send the whole thing back.

```bash
curl -s $SY/api/hosts/12 -H "Authorization: Bearer $KEY" \
  | jq '.upstreams[0].port = 9090' \
  | curl -X PUT $SY/api/hosts/12 -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -d @-
```

**Delete a host** (`hosts.delete`), then apply:

```bash
curl -X DELETE $SY/api/hosts/12 -H "Authorization: Bearer $KEY"
```

**Ban an address for a week** (`bans.add`; no apply needed):

```bash
curl -X POST $SY/api/bans -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"cidr": "203.0.113.9", "reason": "from my IDS", "days": 7}'
```

**Traffic for the last 7 days** (`stats.overview`, `stats.top`):

```bash
curl "$SY/api/stats/overview?range=7d" -H "Authorization: Bearer $KEY"
curl "$SY/api/stats/top?range=7d&dim=country&limit=10" -H "Authorization: Bearer $KEY"
```

## Operations

Every endpoint, with the operation ID an API key needs. "—" means keys
can't use it. Generated from `/api/openapi.json`.

### Hosts

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/hosts` | List hosts, with certificate status | `hosts.list` | viewer or above |
| `POST /api/hosts` | Create a host | `hosts.create` | editor or admin |
| `DELETE /api/hosts/{id}` | Delete a host | `hosts.delete` | editor or admin |
| `GET /api/hosts/{id}` | Get a host | `hosts.get` | viewer or above |
| `PUT /api/hosts/{id}` | Replace a host's settings | `hosts.update` | editor or admin |
| `POST /api/hosts/{id}/move` | Move a host to a folder (null for none) | `hosts.move` | editor or admin |

### Folders

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/folders` | List folders | `folders.list` | viewer or above |
| `POST /api/folders` | Create a folder | `folders.create` | editor or admin |
| `DELETE /api/folders/{id}` | Delete a folder (its hosts become unfiled) | `folders.delete` | editor or admin |
| `PUT /api/folders/{id}` | Replace a folder's settings | `folders.update` | editor or admin |
| `POST /api/folders/{id}/enabled` | Enable or disable every host in a folder | `folders.enabled` | editor or admin |

### Access

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/countries` | ISO country codes and names | `access.countries` | viewer or above |
| `DELETE /api/never-ban` | Remove a never-block entry | `neverban.delete` | editor or admin |
| `GET /api/never-ban` | List never-block addresses | `neverban.list` | viewer or above |
| `POST /api/never-ban` | Never block an IP or CIDR | `neverban.add` | editor or admin |
| `GET /api/policies` | List access policies | `policies.list` | viewer or above |
| `POST /api/policies` | Create an access policy | `policies.create` | editor or admin |
| `DELETE /api/policies/{id}` | Delete an access policy | `policies.delete` | editor or admin |
| `PUT /api/policies/{id}` | Replace an access policy | `policies.update` | editor or admin |
| `GET /api/whoami` | The caller's IP as Switchyard sees it | `access.whoami` | viewer or above |

### DNS

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/dns-providers` | List DNS providers (tokens never shown) | `dns.list` | viewer or above |
| `POST /api/dns-providers` | Add a DNS provider | `dns.create` | admin |
| `DELETE /api/dns-providers/{id}` | Delete a DNS provider | `dns.delete` | admin |
| `PUT /api/dns-providers/{id}` | Change a DNS provider (empty token keeps the old one) | `dns.update` | admin |
| `POST /api/dns-providers/{id}/verify` | Check a DNS provider's token with the provider | `dns.verify` | editor or admin |

### Certificates

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/certificates` | Certificate status for every domain | `certs.list` | viewer or above |
| `POST /api/certificates/retry` | Retry failed certificates now | `certs.retry` | editor or admin |

### Config

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `POST /api/config/apply` | Apply pending changes to Caddy | `config.apply` | editor or admin |
| `GET /api/config/preview` | Pending changes: diff against Caddy's running config | `config.preview` | viewer or above |
| `GET /api/config/versions` | List applied config versions | `config.versions` | viewer or above |
| `GET /api/config/versions/{n}` | One applied config version | `config.version` | viewer or above |
| `GET /api/config/versions/{n}/diff` | Diff of a version against the one before | `config.version.diff` | viewer or above |
| `POST /api/config/versions/{n}/rollback` | Roll back to a version | `config.rollback` | editor or admin |

### Traffic

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/stats/country/{code}` | One country's traffic (ISO code, LAN or unknown) | `stats.country` | viewer or above |
| `GET /api/stats/ip/{ip}` | One IP's requests, ban and never-block status | `stats.ip` | viewer or above |
| `GET /api/stats/overview` | Totals and time series | `stats.overview` | viewer or above |
| `GET /api/stats/tail` | Newest requests (live view) | `stats.tail` | viewer or above |
| `GET /api/stats/top` | Busiest IPs, paths, countries, status classes or hosts | `stats.top` | viewer or above |

### Honeypot

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/bans` | List bans (all=1 for lifted and expired too) | `bans.list` | viewer or above |
| `POST /api/bans` | Ban an IP or CIDR on every host (days 0 = until lifted) | `bans.add` | editor or admin |
| `GET /api/bans/export` | Active bans as a block list (format=json for JSON) | `bans.export` | viewer or above |
| `POST /api/bans/unban` | Lift every ban covering an address | `bans.unban` | editor or admin |
| `DELETE /api/bans/{id}` | Lift a ban | `bans.delete` | editor or admin |
| `GET /api/crowdsec` | CrowdSec settings (key never shown) | `crowdsec.get` | admin |
| `PUT /api/crowdsec` | Change CrowdSec settings | `crowdsec.update` | admin |
| `GET /api/honeypot` | Honeypot settings and trap paths | `honeypot.get` | viewer or above |
| `PUT /api/honeypot` | Change honeypot settings | `honeypot.update` | editor or admin |
| `GET /api/honeypot/activity` | Recent honeypot hits and top sources | `honeypot.activity` | viewer or above |
| `POST /api/honeypot/traps` | Add a trap path | `traps.create` | editor or admin |
| `DELETE /api/honeypot/traps/{id}` | Delete a trap path | `traps.delete` | editor or admin |
| `PUT /api/honeypot/traps/{id}` | Change a trap path | `traps.update` | editor or admin |

### Health

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/alerts` | Open alerts (all=1 for resolved ones too) | `alerts.list` | viewer or above |
| `POST /api/health/check` | Run the health checks now | `health.check` | viewer or above |
| `GET /api/health/details` | Health page: Caddy, applies, drift, disk, GeoIP, alerts | `health.details` | viewer or above |
| `GET /api/status` | Whether Switchyard can reach Caddy | `status.get` | viewer or above |

### Users

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/audit` | Audit log, newest first | `audit.list` | admin |
| `GET /api/backup` | Download a backup of the database | `backup.download` | admin |
| `POST /api/restore` | Restore a backup (replaces everything, API keys included) | — | admin |
| `GET /api/settings` | Sign-in policy | `settings.get` | admin |
| `PUT /api/settings` | Change the sign-in policy | `settings.update` | admin |
| `GET /api/users` | List users | `users.list` | admin |
| `POST /api/users` | Create a user (they choose a new password at first sign-in) | `users.create` | admin |
| `DELETE /api/users/{id}` | Delete a user | `users.delete` | admin |
| `PUT /api/users/{id}` | Change a user's role or disable them | `users.update` | admin |
| `POST /api/users/{id}/password` | Set a temporary password for a user | `users.password` | admin |
| `POST /api/users/{id}/reset-2fa` | Turn off a user's two-factor sign-in | `users.reset2fa` | admin |

### Import

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `POST /api/import/npm/preview` | Read Nginx Proxy Manager and preview an import | `import.preview` | admin |
| `POST /api/import/npm/run` | Run a previewed import | `import.run` | admin |

### API keys

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/keys` | List API keys | — | admin |
| `POST /api/keys` | Make an API key (its token is in the answer, once) | — | admin |
| `GET /api/keys/operations` | Operations a key can be given | — | admin |
| `PUT /api/keys/{id}` | Rename a key or change its permissions | — | admin |
| `POST /api/keys/{id}/revoke` | Revoke a key; it stops working at once | — | admin |

### Account

| Endpoint | What it does | Key permission | Session role |
|---|---|---|---|
| `GET /api/auth/2fa` | Your two-factor sign-in status | — | any signed-in user |
| `POST /api/auth/2fa/begin` | Start setting up two-factor sign-in | — | any signed-in user |
| `POST /api/auth/2fa/confirm` | Confirm two-factor sign-in with a code | — | any signed-in user |
| `POST /api/auth/2fa/disable` | Turn off two-factor sign-in | — | viewer or above |
| `POST /api/auth/login` | Sign in with a username and password | — | none (public) |
| `POST /api/auth/logout` | Sign out | — | none (public) |
| `GET /api/auth/me` | The signed-in user | — | any signed-in user |
| `POST /api/auth/password` | Change your password | — | any signed-in user |
| `GET /api/auth/preferences` | Your display preferences | — | viewer or above |
| `PUT /api/auth/preferences` | Save your display preferences | — | viewer or above |
| `POST /api/auth/totp` | Finish signing in with a two-factor code | — | none (public) |

