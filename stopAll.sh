#!/usr/bin/env bash
set -e
docker rm -f ubi-backend-cpp ubi-frontend 2>/dev/null || true
echo "Stopped containers: ubi-backend-cpp, ubi-frontend"
