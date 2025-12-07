### C++ Transfer Service

A lightweight REST service that shares the same JWT access tokens as the Node auth server. It exposes:

- `POST /transfer` – Authenticated by `Authorization: Bearer <access>`; body includes `direction` (`inbound` or `outbound`), `time` (ISO-8601 string), `amount` (number), and `source` (for inbound) or `destination` (for outbound). Stores the transaction in memory per user.
- `GET /record` – Authenticated; returns the current inbound/outbound arrays for the calling user.
- `POST /auth/register` – Minimal in-memory user registration, returns an access token (HS256, same `JWT_SECRET`).
- `POST /auth/login` – Minimal login, returns an access token.

Tokens: HS256 JWTs signed with `JWT_SECRET` (same value as the Node server). Exp is honored if present.

#### Build
Requires OpenSSL (for HMAC) and a C++17 compiler.

```bash
cd cpp_backend
g++ -std=c++17 -O2 -Iinclude ../cpp_backend/main.cpp -lssl -lcrypto -pthread -o transfer_service
```

Run (choose a port, default 4002):
```bash
JWT_SECRET="your-secret" CPP_PORT=4002 ./transfer_service
```

#### Example
```bash
ACCESS=... # from login

curl -X POST http://localhost:4002/transfer \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{"direction":"outbound","time":"2025-02-10T12:00:00Z","amount":42.5,"destination":"acct-123"}'

curl -H "Authorization: Bearer $ACCESS" http://localhost:4002/record
```

Data is kept in-memory per-process (not persisted).
