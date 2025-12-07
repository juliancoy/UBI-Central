import os
import sys
from pathlib import Path

import docker

ROOT = Path(__file__).resolve().parent


def stop_containers(client: docker.DockerClient) -> None:
  for name in ("ubi-backend-cpp", "ubi-frontend"):
    try:
      container = client.containers.get(name)
      container.remove(force=True)
    except docker.errors.NotFound:
      continue


def start_backend(client: docker.DockerClient) -> None:
  backend_cmd = r"""
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq g++ libssl-dev inotify-tools
cd /work/cpp_backend
while true; do
  echo "[cpp-backend] building..."
  if g++ -std=c++17 -O2 -Iinclude ../cpp_backend/main.cpp -lssl -lcrypto -pthread -o /tmp/transfer_service; then
    echo "[cpp-backend] starting..."
    JWT_SECRET=${JWT_SECRET:-dev-secret} CPP_PORT=${CPP_PORT:-4002} /tmp/transfer_service &
    pid=$!
    # watch for file changes; on change, stop the service to trigger rebuild
    inotifywait -e modify,create,delete -r . >/dev/null 2>&1
    echo "[cpp-backend] change detected, restarting..."
    kill $pid 2>/dev/null || true
    wait $pid || true
  else
    echo "[cpp-backend] build failed, waiting for file changes to retry..."
    inotifywait -e modify,create,delete -r . >/dev/null 2>&1
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
      },
      ports={f"{os.getenv('CPP_PORT', '4002')}/tcp": int(os.getenv("CPP_PORT", "4002"))},
      volumes={str(ROOT): {"bind": "/work", "mode": "rw"}},
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
      environment={"PORT": os.getenv("PORT", "3000")},
      ports={f"{os.getenv('PORT', '3000')}/tcp": int(os.getenv("PORT", "3000"))},
      volumes={str(ROOT): {"bind": "/work", "mode": "rw"}},
  )


if __name__ == "__main__":
  try:
    client = docker.from_env()
    client.ping()
  except Exception as exc:  # noqa: BLE001
    print(f"Docker is required and must be running: {exc}", file=sys.stderr)
    sys.exit(1)

  stop_containers(client)
  start_backend(client)
  start_frontend(client)
  print("Backend: http://localhost:4002  | Frontend: http://localhost:3000")
