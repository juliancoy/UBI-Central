import os
import sys
from pathlib import Path

import docker

ROOT = Path(__file__).resolve().parent

DEFAULT_BACKEND_REPLICAS = 4


def int_from_env(key: str, default: int) -> int:
  raw = os.getenv(key)
  if raw is None:
    return default
  try:
    return int(raw)
  except ValueError:
    return default


def ensure_network(client: docker.DockerClient, name: str) -> str:
  """Create network if it doesn't already exist."""
  for net in client.networks.list(names=[name]):
    return net.name
  client.networks.create(name, driver="bridge")
  return name


def stop_containers(client: docker.DockerClient) -> None:
  for container in client.containers.list(all=True, filters={"name": "ubi-backend-cpp"}):
    container.remove(force=True)
  for name in ("ubi-frontend", "ubi-proxy"):
    try:
      container = client.containers.get(name)
      container.remove(force=True)
    except docker.errors.NotFound:
      continue


def backend_replicas() -> int:
  replicas = int_from_env("CPP_BACKEND_REPLICAS", DEFAULT_BACKEND_REPLICAS)
  # keep things sane; a handful of replicas is enough for local dev
  return min(max(replicas, 1), 10)


def generate_nginx_config(instances: list[tuple[str, int]]) -> Path:
  upstream_entries = "\n".join(f"    server {name}:{port};" for name, port in instances)
  config = f"""events {{}}

http {{
  access_log /dev/stdout;
  error_log /dev/stderr info;

  upstream node_app {{
    server ubi-frontend:3000;
  }}

  upstream cpp_app {{
{upstream_entries}
  }}

  server {{
    listen 80;
    server_name _;
    client_max_body_size 10m;

    location /cpp/ {{
      rewrite ^/cpp(/.*)$ $1 break;
      proxy_pass http://cpp_app;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }}

    location / {{
      proxy_pass http://node_app;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }}
  }}
}}
"""
  generated = ROOT / ".nginx.generated.conf"
  generated.write_text(config)
  return generated


def start_backend(client: docker.DockerClient, name: str, port: int) -> None:
  backend_cmd = r"""
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq g++ libssl-dev inotify-tools curl
cd /work/cpp_backend
while true; do
  echo "[cpp-backend] building..."
  if g++ -std=c++17 -O2 -Iinclude ../cpp_backend/main.cpp -lssl -lcrypto -pthread -o /tmp/transfer_service; then
    echo "[cpp-backend] starting..."
    JWT_SECRET=${JWT_SECRET:-dev-secret} CPP_PORT=${CPP_PORT:-4002} /tmp/transfer_service &
    pid=$!
    # watch for file changes; on change, stop the service to trigger rebuild
    inotifywait -e modify,create,delete -r --exclude '(^|/)(tests|wal\\.log|backups)(/|$)' . >/dev/null 2>&1
    echo "[cpp-backend] change detected, restarting..."
    curl -s -X POST -H "x-admin-key: ${CPP_ADMIN_KEY}" "http://localhost:${CPP_PORT:-4002}/admin/backup" >/dev/null 2>&1 || true
    kill $pid 2>/dev/null || true
    wait $pid || true
  else
    echo "[cpp-backend] build failed, waiting for file changes to retry..."
    inotifywait -e modify,create,delete -r --exclude '(^|/)(tests|wal\\.log|backups)(/|$)' . >/dev/null 2>&1
  fi
done
"""
  client.containers.run(
      "ubuntu:24.04",
      ["bash", "-lc", backend_cmd],
      name=name,
      detach=True,
      remove=True,
      environment={
          "JWT_SECRET": os.getenv("JWT_SECRET", "dev-secret"),
          "CPP_PORT": str(port),
          "CPP_ADMIN_KEY": os.getenv("CPP_ADMIN_KEY", ""),
          "CPP_BACKUP_DIR": os.getenv("CPP_BACKUP_DIR", "/tmp/ubi-backups"),
          "CPP_WAL_PATH": os.getenv("CPP_WAL_PATH", "/tmp/ubi-wal.log"),
          "CPP_TEST_BYPASS_USER": os.getenv("CPP_TEST_BYPASS_USER", "loadtest-user"),
      },
      volumes={str(ROOT): {"bind": "/work", "mode": "rw"}},
      ports={f"{port}/tcp": port},
      network=os.getenv("UBI_NETWORK", "ubi-net"),
  )


def start_frontend(client: docker.DockerClient) -> None:
  frontend_cmd = r"""
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential python3
cd /work
npm install
PORT=${PORT:-3000} npm start
"""
  client.containers.run(
      "node:25",
      ["bash", "-lc", frontend_cmd],
      name="ubi-frontend",
      detach=True,
      remove=True,
      environment={
          "PORT": os.getenv("PORT", "3000"),
          "CPP_BASE_URL": os.getenv("CPP_BASE_URL", "http://ubi-proxy/cpp"),
      },
      volumes={str(ROOT): {"bind": "/work", "mode": "rw"}},
      network=os.getenv("UBI_NETWORK", "ubi-net"),
  )


def start_proxy(client: docker.DockerClient, nginx_conf_path: Path) -> None:
  proxy_cmd = r"""
nginx -g 'daemon off;'
"""
  client.containers.run(
      "nginx:1.27",
      ["bash", "-lc", proxy_cmd],
      name="ubi-proxy",
      detach=True,
      remove=True,
      ports={"80/tcp": int(os.getenv("PROXY_PORT", "8080"))},
      volumes={
          str(nginx_conf_path): {"bind": "/etc/nginx/nginx.conf", "mode": "ro"},
      },
      network=os.getenv("UBI_NETWORK", "ubi-net"),
  )

if __name__ == "__main__":
  try:
    client = docker.from_env()
    client.ping()
  except Exception as exc:  # noqa: BLE001
    print(f"Docker is required and must be running: {exc}", file=sys.stderr)
    sys.exit(1)

  network_name = ensure_network(client, os.getenv("UBI_NETWORK", "ubi-net"))
  base_port = int_from_env("CPP_PORT", 4002)
  replicas = backend_replicas()
  backend_instances = [(f"ubi-backend-cpp-{i+1}", base_port + i) for i in range(replicas)]

  stop_containers(client)
  for name, port in backend_instances:
    start_backend(client, name, port)

  start_frontend(client)
  nginx_conf_path = generate_nginx_config(backend_instances)
  start_proxy(client, nginx_conf_path)
  print("Proxy: http://localhost:8080  (services only available via proxy)")
