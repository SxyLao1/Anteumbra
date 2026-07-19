#!/bin/sh
set -eu

cd "${ANTEUMBRA_HOME:-/app}"

should_bootstrap=false
if [ "${1:-}" = "anteumbra" ] && { [ "${2:-}" = "run" ] || [ "${2:-}" = "start" ]; }; then
  should_bootstrap=true
fi

if [ "$should_bootstrap" != "true" ]; then
  exec "$@"
fi

mkdir -p data/registry data/quarantine data/wal data/sessions data/archives data/threat_intel data/siem logs sites/default rules

if [ ! -f config.toml ]; then
  echo "[Docker] config.toml missing; creating a default runtime config."
  anteumbra config init --output config.toml --force
fi

if [ ! -d rules/webshell ] && [ -d src/anteumbra/rules/webshell ]; then
  mkdir -p rules
  cp -r src/anteumbra/rules/webshell rules/webshell
fi

if python - <<'PY'
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

cfg_path = Path("config.toml")
if not cfg_path.exists():
    raise SystemExit(1)

data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
site_path = str(data.get("website", {}).get("path", "")).replace("\\", "/")
raise SystemExit(0 if site_path == "/var/www/html" else 1)
PY
then
  echo "[Docker] Using bundled website directory sites/default for the default config."
  anteumbra config set website.path sites/default --config config.toml
fi

if python - <<'PY'
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

cfg_path = Path("config.toml")
if not cfg_path.exists():
    raise SystemExit(1)

data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
waf = data.get("waf_source", {})
source_type = str(waf.get("type", "mock")).lower()
url = str(waf.get("url", "")).lower()
is_default_mock = source_type == "mock" and ("127.0.0.1" in url or "localhost" in url)
raise SystemExit(0 if waf.get("enabled", False) is True and is_default_mock else 1)
PY
then
  echo "[Docker] Disabling default MockWAF polling; configure waf_source to enable a real WAF feed."
  anteumbra config set waf_source.enabled false --config config.toml
fi

python - <<'PY'
import socket
import struct
from pathlib import Path

import tomli_w

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def default_gateway() -> str | None:
    try:
        routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return None

    for route in routes:
        fields = route.split()
        if len(fields) < 4 or fields[1] != "00000000":
            continue
        try:
            flags = int(fields[3], 16)
            gateway = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
        except (OSError, ValueError, struct.error):
            continue
        if flags & 0x2:
            return gateway
    return None


config_path = Path("config.toml")
gateway = default_gateway()
if gateway and config_path.exists():
    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    web_admin = data.get("web_admin", {})
    allowed_ips = web_admin.get("allowed_ips")
    if allowed_ips == ["127.0.0.1"] and gateway != "127.0.0.1":
        web_admin["allowed_ips"] = ["127.0.0.1", gateway]
        config_path.write_text(tomli_w.dumps(data), encoding="utf-8")
        print(f"[Docker] Allowed the local Docker gateway {gateway} to access the admin UI.")
PY

if [ ! -f .env ]; then
  python - <<'PY'
import os
import secrets
import string
from pathlib import Path
from werkzeug.security import generate_password_hash

env_path = Path(".env")
password = os.environ.get("ANTEUMBRA_ADMIN_PASSWORD")
password_hash = os.environ.get("ANTEUMBRA_PASSWORD_HASH")
generated = False

if not password_hash:
    if not password:
        alphabet = string.ascii_letters + string.digits
        password = "".join(secrets.choice(alphabet) for _ in range(16))
        generated = True
    password_hash = generate_password_hash(password)

secret_key = os.environ.get("ANTEUMBRA_SECRET_KEY") or secrets.token_urlsafe(32)

env_path.write_text(
    "# Anteumbra Docker runtime environment\n"
    f"ANTEUMBRA_PASSWORD_HASH={password_hash}\n"
    f"ANTEUMBRA_SECRET_KEY={secret_key}\n"
    "ANTEUMBRA_EMAIL_USERNAME=\n"
    "ANTEUMBRA_EMAIL_PASSWORD=\n"
    "ANTEUMBRA_EMAIL_FROM=\n"
    "ANTEUMBRA_EMAIL_TO=\n"
    "ANTEUMBRA_WECHAT_API_KEY=\n"
    "ANTEUMBRA_WAF_API_KEY=\n",
    encoding="utf-8",
)

print("")
print("=" * 60)
print("  Anteumbra Docker first start")
print("  Admin URL:  http://127.0.0.1:8080/admin")
print("  Username:   admin")
if password and generated:
    print(f"  Password:   {password}")
elif password:
    print("  Password:   from ANTEUMBRA_ADMIN_PASSWORD")
else:
    print("  Password:   from ANTEUMBRA_PASSWORD_HASH")
print("  Saved to:   /app/.env")
print("=" * 60)
print("")
PY
fi

exec "$@"
