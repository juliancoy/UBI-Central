#!/usr/bin/env bash
set -e
docker ps -a --filter "name=ubi-backend-cpp" -q | xargs -r docker rm -f
docker rm -f ubi-frontend ubi-proxy 2>/dev/null || true
echo "Stopped containers: ubi-backend-cpp*, ubi-frontend, ubi-proxy"
