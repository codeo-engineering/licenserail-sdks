#!/usr/bin/env bash
# Starts a throwaway PostgreSQL and the API on this computer (Linux, macOS, Windows with Git Bash) for e2e/run.mjs.
#   e2e/start-api.sh <folder of the published API> <work folder>
# Needs the .NET 10 runtime and PostgreSQL's server programs (PGBIN, or found in the usual places).
set -euo pipefail
api_dir=$1
work=$2
mkdir -p "$work/mail"

if [ -z "${PGBIN:-}" ]; then
  for d in /usr/lib/postgresql/*/bin /opt/homebrew/opt/postgresql@*/bin /usr/local/opt/postgresql@*/bin "/c/Program Files/PostgreSQL"/*/bin; do
    if [ -d "$d" ]; then PGBIN=$d; fi
  done
fi
[ -n "${PGBIN:-}" ] || { echo "PostgreSQL not found; set PGBIN."; exit 1; }
if command -v cygpath >/dev/null; then PGBIN=$(cygpath -u "$PGBIN"); fi

"$PGBIN/initdb" -D "$work/pg" -U postgres -A trust -E UTF8 --locale=C > "$work/initdb.log"
# Output redirected: the server would keep this script's output open.
"$PGBIN/pg_ctl" -D "$work/pg" -o "-p 5544 -c listen_addresses=127.0.0.1 -c unix_socket_directories=" -l "$work/pg.log" -w start > /dev/null 2>&1
"$PGBIN/createdb" -h 127.0.0.1 -p 5544 -U postgres licensing

(
  cd "$api_dir"
  env ASPNETCORE_ENVIRONMENT=Development ASPNETCORE_URLS=http://127.0.0.1:5090 RateLimiting__Enabled=false \
    "ConnectionStrings__Licensing=Host=127.0.0.1;Port=5544;Database=licensing;Username=postgres" \
    "Mail__OutboxDirectory=$work/mail" Admin__Email=e2e@example.local Admin__Password=e2e-password-123 Admin__DisplayName=E2E \
    nohup dotnet LicenseRail.Api.dll > "$work/api.log" 2>&1 &
)
for _ in $(seq 1 60); do
  if curl -fs -m 2 http://127.0.0.1:5090/health > /dev/null; then echo "API is up."; exit 0; fi
  sleep 1
done
tail -50 "$work/api.log"
exit 1
