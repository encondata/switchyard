# Cutover from Nginx Proxy Manager to CPM

Runbook for card CPM-27. It moves ports 80 and 443 from NPM to CPM's Caddy
on the same server, keeps NPM ready to come back, and retires it after two
quiet weeks.

**Time needed:** about an hour, plus the two-week watch period.
**Downtime:** under a minute while ports move (Caddy may need another minute
per new certificate).

## 1. Before the day

1. **Check NPM for streams** (NPM → Hosts → Streams). CPM doesn't forward raw
   TCP/UDP. Move any streams to a VPN or keep a small separate forwarder.
2. **Back up NPM:** stop nothing yet; copy its data and certificates:
   ```bash
   docker cp npm:/data ./npm-backup-data
   docker cp npm:/etc/letsencrypt ./npm-backup-letsencrypt
   ```
3. **Install CPM** on the server next to NPM, but **don't publish ports 80/443
   yet**. In `compose.yaml`, temporarily change Caddy's ports to
   `8081:80` and `8443:443` (leave CPM's UI on `8080`, LAN only).
   ```bash
   cp .env.example .env
   echo "CPM_SECRET_KEY=$(openssl rand -base64 32)" >> .env   # keep a copy somewhere safe
   docker compose up -d --build
   ```
4. **Sign in** (admin / 123456), set a real password, then on **Account**
   turn on two-factor sign-in. Add other users on **Users**.
5. **Never block:** on **Access**, add your office/VPN addresses.
6. **DNS:** if NPM used DNS-challenge or wildcard certificates, add the
   Cloudflare token on **DNS** (Zone → Zone → Read and Zone → DNS → Edit), test
   it, and set it as the default on the folders that need it.

## 2. Import and review (no traffic yet)

1. **Hosts → Import from NPM**, upload `npm-backup-data/database.sqlite`
   (or give the MySQL details). Read the preview: warnings list everything
   that isn't converted (custom nginx config, custom locations, basic auth).
2. Import. Every host lands **disabled** in the **Imported** folder.
3. For each host:
   - compare with NPM (domains, upstream, HTTPS, access list → policy);
   - recreate anything from the notes that matters (custom config → advanced
     JSON or headers);
   - hosts that used a DNS-challenge certificate: switch them to
     **DNS challenge**;
   - enable it.
4. Move hosts into folders and attach policies to folders where it makes
   sense.
5. **Review & apply.** Caddy validates the whole config; fix anything it
   rejects.

## 3. Test on the side ports

From a machine that can reach the server, check each host through the
temporary ports without touching DNS:

```bash
curl -s -o /dev/null -w '%{http_code}\n' --resolve app.example.com:8081:SERVER_IP http://app.example.com:8081/
curl -sk -o /dev/null -w '%{http_code}\n' --resolve app.example.com:8443:SERVER_IP https://app.example.com:8443/
```

Public certificates can't be issued on the side ports (Let's Encrypt only
uses 80/443), so expect certificate warnings until the switch. DNS-challenge
hosts get real certificates now; check **Certificates**.

## 4. Switch (the few minutes of downtime)

1. Announce a short window.
2. Stop NPM (don't remove it):
   ```bash
   docker stop npm
   ```
3. Put Caddy's ports back to `80:80`, `443:443`, `443:443/udp` in
   `compose.yaml`, then:
   ```bash
   docker compose up -d
   ```
4. Watch **Certificates**: HTTP-challenge certificates are issued within a
   minute or two. **Retry now** if one is slow; read the error if it fails.
5. Check every host from outside (browser and `curl`), including an access
   policy from an address that should be blocked.
6. Check **Health**: Caddy reachable, config matches CPM, no alerts.

## 5. Roll back if needed

Within the two weeks, NPM can come back in a minute:

```bash
docker compose stop caddy
docker start npm
```

Its data and certificates are untouched. Fix the problem in CPM (on the side
ports again if needed) and switch again.

## 6. Watch for two weeks, then retire NPM

- Daily: **Health** and **Certificates**; the banner shows any alert.
- After a week: download a backup on **Health** and store it with the
  `CPM_SECRET_KEY`.
- After two quiet weeks:
  ```bash
  docker rm npm        # keep npm-backup-* for another month
  ```
- Move this card to Done.
