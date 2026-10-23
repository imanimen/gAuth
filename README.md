# gAuth

gAuth is a complete authentication microservice for production applications, built in Go.

## Features

- Email OTP registration / login flow (send, resend, verify)
- Google OAuth 2.0 social login with account linking
- JWT access tokens (HS256, configurable TTL)
- User profile management (key/value profiles, favorite categories, username validation, registration steps)
- User directory with search & pagination
- Swagger UI generated from annotations (mounted at `/swagger/*` when `ENABLE_SWAGGER=true`)
- Dependency injection with [Uber fx](https://github.com/uber-go/fx), MySQL via GORM

## Quick start

```bash
cp .env.example .env   # fill in dsn, SECRET, Google credentials
make run
```

Server listens on `:8080` (`PORT` env). API docs at `http://localhost:8080/swagger/index.html`.

## Development

```bash
make verify     # fmt + vet + build + tests
make test       # unit + e2e route tests (SQLite in-memory, no external deps)
make swag       # regenerate OpenAPI docs after annotating handlers
make build      # build binary
```

## Environment variables

See `.env.example`. Key values:

- `dsn` — MySQL DSN
- `SECRET` — JWT signing secret (`jWT` legacy name still supported)
- `TOKEN_TTL` — access token lifetime (default `10m`)
- `ENABLE_SWAGGER` — expose the Swagger UI
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URL` — OAuth credentials
- `NOTIFY_API_URL` / `FILE_SERVICE_URL` / `CDN_URL` — optional service integrations

## Project layout

```
providers/    config, database (GORM), API handlers, validation, DTOs
services/     JWT token manager, OAuth provider client, HTTP helpers
middlewares/  auth middleware (sets user + platform on the request context)
models/       GORM models (User, OTP, Profile, SocialAuth)
invokers/     router factory, HTTP server lifecycle
tests/        end-to-end route tests over the real router
```

## Notes

- All endpoints speak JSON and return the `{version, data, error}` envelope.
- `POST /api/user/:id` (the unauthenticated duplicate of user lookup) was removed; the authenticated `GET /auth/user/:id` is the single source of truth.
- The legacy Postman collection (`fx-auth.postman_collection.json`) used form-encoded bodies and predates the JSON migration — the Swagger docs describe the current contract.
