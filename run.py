import os
import sys
from pathlib import Path

import docker

ROOT = Path(__file__).resolve().parent


def ensure_network(client: docker.DockerClient, name: str) -> str:
  """Create network if it doesn't already exist."""
  for net in client.networks.list(names=[name]):
    return net.name
  client.networks.create(name, driver="bridge")
  return name


def stop_containers(client: docker.DockerClient) -> None:
  for name in ("ubi-backend-cpp", "ubi-frontend", "ubi-proxy"):
    try:
      container = client.containers.get(name)
      container.remove(force=True)
    except docker.errors.NotFound:
      continue


def start_backend(client: docker.DockerClient) -> None:
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
      name="ubi-backend-cpp",
      detach=True,
      remove=True,
      environment={
          "JWT_SECRET": os.getenv("JWT_SECRET", "dev-secret"),
          "CPP_PORT": os.getenv("CPP_PORT", "4002"),
          "CPP_ADMIN_KEY": os.getenv("CPP_ADMIN_KEY", ""),
          "CPP_BACKUP_DIR": os.getenv("CPP_BACKUP_DIR", "/tmp/ubi-backups"),
          "CPP_WAL_PATH": os.getenv("CPP_WAL_PATH", "/tmp/ubi-wal.log"),
          "CPP_TEST_BYPASS_USER": os.getenv("CPP_TEST_BYPASS_USER", "loadtest-user"),
      },
      volumes={str(ROOT): {"bind": "/work", "mode": "rw"}},
      ports={f"{os.getenv('CPP_PORT', '4002')}/tcp": int(os.getenv("CPP_PORT", "4002"))},
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
          "CPP_BASE_URL": os.getenv("CPP_BASE_URL", "http://ubi-backend-cpp:4002"),
      },
      volumes={str(ROOT): {"bind": "/work", "mode": "rw"}},
      network=os.getenv("UBI_NETWORK", "ubi-net"),
  )

def start_proxy(client: docker.DockerClient) -> None:
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
          str(ROOT / "nginx.conf"): {"bind": "/etc/nginx/nginx.conf", "mode": "ro"},
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

  stop_containers(client)
  start_backend(client)
  start_frontend(client)
  start_proxy(client)
  print("Proxy: http://localhost:8080  (services only available via proxy)")
