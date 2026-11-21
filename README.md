# node_keyvault

API ([Hono](https://hono.dev)) + UI (React + Vite) สำหรับจัดการ secret (CRUD) โดยรองรับ 2 โหมด:

- `local` (ค่าเริ่มต้น): ใช้ Vault container ใน Docker สำหรับ local development
- `azure`: ใช้ Azure Key Vault จริงผ่าน `@azure/identity` + `@azure/keyvault-secrets`

## Run ด้วย Docker Compose (local dev)

```bash
cp .env.example .env
docker compose up --build
```

บริการที่ได้:

- App: `http://localhost:3000`
- Azure Key Vault emulator ([Lowkey Vault](https://github.com/nagyesta/lowkey-vault)): `https://localhost:8443` (self-signed cert)

ใน compose แอพจะใช้ `SECRET_PROVIDER=azure` คุยกับ emulator ผ่าน Azure SDK ตัวจริง (token มาจาก managed identity endpoint ปลอมที่ port 8080)

### UI

เปิด `http://localhost:3000` แล้วใช้งานฟอร์ม CRUD ได้ทันที

### ตัวอย่างเรียกใช้งาน API

`/secrets/*` ต้องแนบ `Authorization: Bearer <access_token>` (ได้จาก OAuth2 flow ด้านล่าง)

```bash
curl -X PUT http://localhost:3000/secrets/demo \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"hello-local"}'

curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:3000/secrets/demo

curl -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:3000/secrets/demo
```

## Run แบบ local (ไม่ใช้ docker app)

```bash
pnpm install
cp .env.example .env
docker compose up -d keyvault mongo   # รัน emulator + MongoDB
pnpm dev                        # API :3000 + UI (Vite) http://localhost:5173
```

## สลับไป Azure Key Vault จริง

```bash
# ใน .env ลบ block emulator (AZURE_KEYVAULT_URL, IDENTITY_*, NODE_TLS_REJECT_UNAUTHORIZED)
# แล้วใส่ AZURE_KEYVAULT_URL / AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
```

## Authentication

แอพเป็น OAuth2 Authorization Server ของตัวเอง (เก็บข้อมูลใน MongoDB ด้วย native driver)

- **OAuth2 Authorization Code + PKCE (S256)** — React UI เป็น public client `keyvault-web`
- **Password** — hash ด้วย argon2id
- **Passkey (WebAuthn)** — ใช้ fido2-lib แบบ discoverable credential (sign-in โดยไม่ต้องพิมพ์ username)
- **Token แบบ opaque** — access token (15 นาที) + refresh token (30 วัน, rotation + reuse detection) เก็บใน Mongo เป็น SHA-256 hash เท่านั้น

Flow: UI → `GET /oauth/authorize` → redirect ไป `/login?request_id=…` → login ด้วย password หรือ passkey → redirect กลับ `/callback?code=…` → UI แลก code ที่ `POST /oauth/token` ด้วย `code_verifier`

เพิ่ม passkey ได้จากปุ่ม "Add passkey" หลัง login (ทดสอบบน Chrome ได้ด้วย DevTools → More tools → WebAuthn → virtual authenticator)

ตั้งค่าใน `.env`: `MONGO_URL`, `MONGO_DB`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS`, `OAUTH_CLIENT_ID`, `OAUTH_REDIRECT_URIS`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL` (ดู `.env.example`)
— `WEBAUTHN_ORIGINS` และ `OAUTH_REDIRECT_URIS` ต้องตรงกับ origin ที่เปิด UI จริง (dev: `:5173`, build: port ของ API)

## Endpoint

- `GET /health`
- `GET /oauth/authorize` · `POST /oauth/token` · `POST /oauth/revoke` · `GET /oauth/userinfo` (Bearer)
- `POST /auth/register` · `POST /auth/login/password`
- `POST /auth/webauthn/login/options` · `POST /auth/webauthn/login/verify`
- `POST /auth/webauthn/register/options` · `POST /auth/webauthn/register/verify` · `GET/DELETE /auth/webauthn/credentials` (Bearer)

Secrets (ต้องมี Bearer token):

- `GET /secrets` (list ชื่อ + วันที่ ไม่มี value)
- `GET /secrets/:name`
- `PUT /secrets/:name` body: `{ "value": "..." }`
- `DELETE /secrets/:name`
