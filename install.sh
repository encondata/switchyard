#!/usr/bin/env bash
# Switchyard installer: Caddy and its web manager, on Docker.
#
#   curl -fsSL https://raw.githubusercontent.com/encondata/switchyard/main/install.sh | bash
#
# Clones or updates the repository, makes the encryption key on first run,
# picks free ports, builds and starts the stack, and waits until the web UI
# answers. Safe to run again: it updates the code and restarts, and never
# overwrites .env (the key and ports you already have).
#
# Settings, all optional (for unattended installs):
#   SWITCHYARD_DIR         where to install
#   SWITCHYARD_BRANCH      branch to run (default main)
#   SWITCHYARD_REPO        repository to clone
#   SWITCHYARD_HTTP_PORT   SWITCHYARD_HTTPS_PORT   SWITCHYARD_UI_PORT
#                          ports to publish on a first install (default 80,
#                          443, 8080; the next free port is offered if taken)
set -euo pipefail

REPO="${SWITCHYARD_REPO:-https://github.com/encondata/switchyard.git}"
BRANCH="${SWITCHYARD_BRANCH:-main}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\n\033[33m%s\033[0m\n' "$*" >&2; }
die() { printf '\n\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# Questions go to the terminal even under curl | bash (where standard input
# is the script). With no terminal at all, the suggested answer is used.
ask() { # ask "question" default -> answer on stdout
  local answer=""
  if { exec 3</dev/tty; } 2>/dev/null; then
    printf '%s [%s] ' "$1" "$2" > /dev/tty
    read -r answer <&3 || answer=""
    exec 3<&-
  fi
  printf '%s' "${answer:-$2}"
}

command -v git >/dev/null 2>&1 || die "git is not installed."
command -v curl >/dev/null 2>&1 || die "curl is not installed."
command -v docker >/dev/null 2>&1 || die "Docker is not installed. See https://docs.docker.com/get-docker/"
docker compose version >/dev/null 2>&1 || die "This needs Docker Compose v2 (the 'docker compose' command)."
docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start it and try again."

# Where it goes. Suggested: where it runs now, so an update is just Enter;
# otherwise the array on Unraid, or the home directory.
RUNNING_WD="$(docker ps -a --filter label=com.docker.compose.service=cpm \
  --filter label=com.docker.compose.project=switchyard \
  --format '{{ .Label "com.docker.compose.project.working_dir" }}' 2>/dev/null | head -1 || true)"
if [ -n "$RUNNING_WD" ]; then DEFAULT_DIR="$RUNNING_WD"
elif [ -d /mnt/user ]; then DEFAULT_DIR=/mnt/user/appdata/switchyard
else DEFAULT_DIR="$HOME/switchyard"; fi
DIR="${SWITCHYARD_DIR:-}"
[ -n "$DIR" ] || DIR="$(ask $'\nInstall Switchyard where?' "$DEFAULT_DIR")"
case "$DIR" in "~"*) DIR="$HOME${DIR#\~}" ;; esac
DIR="${DIR%/}"
case "$DIR" in /*) ;; *) die "Please give a full path, starting with /." ;; esac
if [ -d "$DIR" ] && [ ! -d "$DIR/.git" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
  die "$DIR already has other files in it. Choose an empty or new folder."
fi

# The compose file lives in the repository, so the code comes first.
if [ -d "$DIR/.git" ]; then
  say "Updating $DIR"
  git -C "$DIR" fetch --depth 1 origin "$BRANCH"
  git -C "$DIR" checkout -q "$BRANCH"
  git -C "$DIR" reset -q --hard "origin/$BRANCH"
else
  say "Downloading Switchyard into $DIR"
  mkdir -p "$(dirname "$DIR")"
  git clone -q --depth 1 --branch "$BRANCH" "$REPO" "$DIR"
fi
cd "$DIR"

# Is something listening on this port already (another proxy, an old install)?
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
next_free() { local p="$1"; while port_busy "$p"; do p=$((p + 1)); done; printf '%s' "$p"; }
# pick_port NAME DEFAULT FALLBACK_START "what it is" -> chosen port on stdout
pick_port() {
  local preset="${!1:-}" want="$2" free
  if [ -n "$preset" ]; then printf '%s' "$preset"; return; fi
  if ! port_busy "$want"; then printf '%s' "$want"; return; fi
  free="$(next_free "$3")"
  { printf '\033[33mPort %s (%s) is already in use on this machine.\033[0m\n' "$want" "$4" > /dev/tty; } 2>/dev/null || true
  ask "Use which port for $4 instead?" "$free"
}

rand_key() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 32
  else head -c 32 /dev/urandom | base64 | tr -d '\n'; fi
}

if [ ! -f .env ]; then
  say "First install: making the encryption key and choosing ports"
  HTTP_PORT="$(pick_port SWITCHYARD_HTTP_PORT 80 8000 'HTTP')"
  HTTPS_PORT="$(pick_port SWITCHYARD_HTTPS_PORT 443 8443 'HTTPS')"
  UI_PORT="$(pick_port SWITCHYARD_UI_PORT 8080 8081 'the web UI')"
  # Created private (umask) so the key is never readable by others, even briefly.
  (umask 077; {
    printf '# Made by install.sh. Docker Compose reads this file; never commit it.\n\n'
    printf '# Encrypts DNS provider tokens in the database. Keep a copy somewhere safe:\n'
    printf '# without it, stored tokens cannot be decrypted after a restore.\n'
    printf 'CPM_SECRET_KEY=%s\n\n' "$(rand_key)"
    printf '# Published ports. Caddy needs 80 and 443 to get real certificates;\n'
    printf '# other ports are for testing next to another proxy.\n'
    printf 'SWITCHYARD_HTTP_PORT=%s\n' "$HTTP_PORT"
    printf 'SWITCHYARD_HTTPS_PORT=%s\n' "$HTTPS_PORT"
    printf 'SWITCHYARD_UI_PORT=%s\n\n' "$UI_PORT"
    printf "# Optional: Let's Encrypt staging while testing, and a contact email.\n"
    printf '# CPM_ACME_CA=https://acme-staging-v02.api.letsencrypt.org/directory\n'
    printf '# CPM_ACME_EMAIL=ops@example.com\n\n'
    printf '# Optional: GeoLite2 country data (free MaxMind account). Set both, then\n'
    printf '# run this installer again to start the geoip updater.\n'
    printf '# GEOIPUPDATE_ACCOUNT_ID=\n'
    printf '# GEOIPUPDATE_LICENSE_KEY=\n'
  } > .env)
fi

setting() { sed -n "s/^$1=//p" .env | tail -1; }
HTTP_PORT="$(setting SWITCHYARD_HTTP_PORT)"; HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="$(setting SWITCHYARD_HTTPS_PORT)"; HTTPS_PORT="${HTTPS_PORT:-443}"
UI_PORT="$(setting SWITCHYARD_UI_PORT)"; UI_PORT="${UI_PORT:-8080}"
PROFILES=()
[ -n "$(setting GEOIPUPDATE_LICENSE_KEY)" ] && PROFILES+=(--profile geoip)

report() {
  printf '\n\033[1mContainers:\033[0m\n' >&2
  docker compose ps -a >&2 || true
  for svc in caddy cpm; do
    printf '\n\033[1mLast lines from %s:\033[0m\n' "$svc" >&2
    docker compose logs --no-color --tail 25 "$svc" >&2 2>&1 || true
  done
}

say "Building and starting (the first build takes a few minutes)"
if ! docker compose ${PROFILES[@]+"${PROFILES[@]}"} up -d --build --remove-orphans; then
  report
  die "Switchyard could not be started; the reason is above. If a port is taken, change it in $DIR/.env and run this again."
fi

BASE="http://127.0.0.1:$UI_PORT"
printf '\nWaiting for the web UI'
UP=no
for _ in $(seq 1 90); do
  if curl -fsS "$BASE/api/health" >/dev/null 2>&1; then UP=yes; break; fi
  printf '.'; sleep 2
done
printf '\n'
if [ "$UP" != yes ]; then
  report
  die "The web UI did not answer on $BASE within three minutes; the reason is above. Your settings are kept; fix it and run this again."
fi

# Only promise the first-run login if it really is still the first-run login.
FIRST_LOGIN=no
CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H "Origin: $BASE" \
  --data '{"username":"admin","password":"123456"}' "$BASE/api/auth/login" 2>/dev/null || true)"
[ "$CODE" = 200 ] && FIRST_LOGIN=yes

# The address other machines use: this machine's IP on its default route.
host_ip() {
  local ip="" ifc=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
  fi
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -z "$ip" ] && command -v route >/dev/null 2>&1; then # macOS
    ifc="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
    [ -n "$ifc" ] && ip="$(ipconfig getifaddr "$ifc" 2>/dev/null)"
  fi
  printf '%s' "${ip:-localhost}"
}
HOST_IP="$(host_ip || true)"
PROJECT="$(docker compose config --format json 2>/dev/null | sed -n 's/^ *"name": *"\([^"]*\)".*/\1/p' | head -1)"

say "Switchyard is up."
cat <<SUMMARY

  Web UI           http://$HOST_IP:$UI_PORT
  Caddy serves     HTTP on port $HTTP_PORT, HTTPS on port $HTTPS_PORT

  Installed in     $DIR
  Settings         $DIR/.env  (keep a copy of CPM_SECRET_KEY)
  Data             Docker volumes named ${PROJECT:-switchyard}_*
SUMMARY

if [ "$FIRST_LOGIN" = yes ]; then
cat <<'LOGIN'

  Sign in with

    Username  admin
    Password  123456

  You'll be asked to choose a new password straight away.
LOGIN
else
cat <<'LOGIN'

  An administrator has already set their own password, so sign in as usual.
LOGIN
fi

if [ "$HTTP_PORT" != 80 ] || [ "$HTTPS_PORT" != 443 ]; then
  warn "Caddy is on ports $HTTP_PORT/$HTTPS_PORT, not 80/443. That's fine for testing, but Let's Encrypt needs 80 and 443: change SWITCHYARD_HTTP_PORT and SWITCHYARD_HTTPS_PORT in $DIR/.env and run this again once your old proxy is off them."
fi

cat <<TAIL

  Coming from Nginx Proxy Manager? Hosts -> Import from NPM reads it
  straight from its admin address.

  Update  run this installer again
  Logs    docker compose -f $DIR/compose.yaml logs -f
  Stop    docker compose -f $DIR/compose.yaml down
TAIL
