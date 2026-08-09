#!/bin/sh
set -e

echo "[standalone] aliasing service names -> 127.0.0.1"
for h in postgres minio mailpit; do
  grep -q "[[:space:]]$h\$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $h" >> /etc/hosts
done

export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://bench@postgres:5432/bench}"
export VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
export APP_DEBUG="${APP_DEBUG:-true}"

PGBIN="$(ls -d /usr/lib/postgresql/*/bin | tail -1)"
export PGDATA=/var/lib/pgdata
mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "[standalone] initdb (trust auth)"
  su postgres -c "$PGBIN/initdb -D $PGDATA -U bench --auth-host=trust --auth-local=trust" >/dev/null
fi

echo "[standalone] starting postgres"
su postgres -c "$PGBIN/pg_ctl -D $PGDATA -o \"-c listen_addresses='127.0.0.1' -p 5432\" -w -t 30 start"
su postgres -c "$PGBIN/createdb -h 127.0.0.1 -U bench bench" 2>/dev/null || true

echo "[standalone] starting internal Mailpit-like sink (:8025)"
python - <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Mailpit standalone internal sink FASTAPI-INTERNAL-SINK"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
HTTPServer(("127.0.0.1", 8025), H).serve_forever()
PY

echo "[standalone] applying schema + seed"
python -m app.seed

echo "[standalone] starting FastAPI"
exec uvicorn app.main:app --host 0.0.0.0 --port 3000
