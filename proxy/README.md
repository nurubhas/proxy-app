# Static-auth Proxy (container)

This container runs a lightweight Express proxy that enforces static Basic Auth (credentials from environment variables) and forwards requests to your existing backend. The backend URL is not exposed to end users — all traffic goes through this proxy.

Environment variables:
- `BACKEND_URL` (required) — full backend URL including protocol, e.g. `https://api.example.com`
- `AUTH_USER` (required) — username for Basic Auth
- `AUTH_PASS` (required) — password for Basic Auth
- `PORT` (optional) — port to listen on inside container (default 8080)

Build and run with Docker:

```bash
docker build -t static-auth-proxy .
docker run -p 8080:8080 \
  -e BACKEND_URL="https://backend.example.com" \
  -e AUTH_USER="alice" \
  -e AUTH_PASS="s3cret" \
  static-auth-proxy
```

Or using docker-compose (create `.env` with the variables):

```bash
docker-compose up --build
```

Notes and tips:
- The proxy preserves request paths and rewrites `Location` response headers from the backend so redirects stay on the proxy host.
- For production, run the container behind a TLS-terminating load balancer or attach a managed certificate. If you control DNS, point a domain/subdomain to this proxy to completely hide the backend URL.
