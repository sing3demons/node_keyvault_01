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
docker compose up -d keyvault mongo   # รัน emulator + MongoDB (หรือ postgres ถ้า AUTH_DB=postgres)
pnpm dev                        # API :3000 + UI (Vite) http://localhost:5173
```

## สลับไป Azure Key Vault จริง

```bash
# ใน .env ลบ block emulator (AZURE_KEYVAULT_URL, IDENTITY_*, NODE_TLS_REJECT_UNAUTHORIZED)
# แล้วใส่ AZURE_KEYVAULT_URL / AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
```

## Authentication

แอพเป็น OAuth2 Authorization Server ของตัวเอง เลือก storage ได้ด้วย `AUTH_DB`:

| `AUTH_DB` | storage | หมายเหตุ |
|---|---|---|
| `mongo` (default) | MongoDB native driver (`MONGO_URL`, `MONGO_DB`) | หมดอายุด้วย TTL index |
| `postgres` | PostgreSQL ผ่าน Drizzle ORM (`DATABASE_URL`) | migration ใน `./drizzle` รันอัตโนมัติตอน start, ลบแถวหมดอายุทุก 10 นาที |

**OpenID Connect (ID Token)**

- ขอ scope `openid` (เพิ่ม `profile`, `email` ได้) แล้ว `/oauth/token` จะคืน `id_token` (JWT, RS256) มาด้วย ทั้งตอนแลก code และตอน refresh
- claim: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce` (ส่งมาตอน `/oauth/authorize`), `at_hash` และตาม scope — `profile`: `name`, `given_name`, `family_name`, `locale`, `preferred_username`, ชื่อแยกภาษา `given_name#th`; `email`: `email`, `email_verified`
- client ตรวจลายเซ็นด้วย `GET /.well-known/jwks.json` (หาได้จาก `GET /.well-known/openid-configuration`)
- ตั้ง `OIDC_ISSUER` เป็น URL จริงใน production (ดู `.env.example`)
- **Signing key rotation** — key เก็บใน Key Vault (secret `oidc-signing-keys`, ตั้งชื่อได้ด้วย `OIDC_KEYS_SECRET`)
  - start ครั้งแรกสร้าง key ให้เอง; key `active` ใช้เซ็น, key `retired` ไม่เซ็นแล้วแต่ยังอยู่ใน JWKS จนหมด `OIDC_RETIRED_KEY_GRACE_SEC` (private key ถูกลบทันทีที่ retire)
  - rotate อัตโนมัติเมื่อ key อายุครบ `OIDC_KEY_ROTATION_DAYS` (30 วัน) หรือสั่งเองด้วย `pnpm oidc:rotate` (image: `node dist/cli/rotate-oidc-key.js`)
  - ทุก instance โหลด key จาก Key Vault ใหม่ทุก `OIDC_KEYS_SYNC_SEC` (5 นาที)
  - secret นี้ถูกซ่อนจาก `/secrets` และอ่าน/เขียน/ลบผ่าน API ไม่ได้ (403)
- `/oauth/userinfo` คืน claim ตาม scope ของ access token เหมือนกัน

**User model**

- `email` (unique, lowercase) และ `profiles: [{ lang, firstName, lastName }]` — ชื่อแยกตามภาษา (BCP 47 เช่น `th`, `en`, `en-US`) ภาษาละ 1 ชุด
- `preferredLang` — ภาษาที่ใช้แสดงชื่อ เลือกได้เฉพาะภาษาที่มีใน `profiles`; ไม่เลือก = ใช้ชุดแรก (`displayProfile`)
- `GET /auth/me` / `PATCH /auth/me` (Bearer) ดูและแก้ `email`, `profiles`, `preferredLang` (`null` = ล้างค่า)
- `/oauth/userinfo` คืน claim ตาม OpenID Connect: `email`, `name`, `given_name`, `family_name`, `locale` และแยกภาษา เช่น `given_name#th`

หนึ่ง user มีได้หลาย credential (`User.credentials[]`):

```ts
type Credential =
  | { type: "password"; value: string; algorithm: "argon2id" | "bcrypt"; ... }
  | { type: "webauthn"; webauthn: { credId, publicKeyPem, counter, transports, name }; ... }
```

- Mongo: ฝังเป็น array ใน document `users` (unique index บน `credentials.key`)
- Postgres: ตาราง `user_credentials` หนึ่งแถวต่อ credential (CHECK constraint ตาม `type`, password ได้ 1 อันต่อ user)
- password ที่ `algorithm` ไม่ใช่ argon2id (เช่น import มาจากระบบอื่น) จะถูก verify แล้ว upgrade เป็น argon2id ตอน login — เพิ่มตัว verify ได้ที่ [src/shared/hashing.ts](src/shared/hashing.ts)
- ลบ credential สุดท้ายของ user ไม่ได้

โค้ด auth ทั้งหมดคุยผ่าน `AuthRepository` ([src/auth/repository.ts](src/auth/repository.ts)) — เพิ่ม DB ใหม่ได้โดย implement interface นี้ใน `src/auth/repositories/` แล้วเพิ่มใน `createAuthRepository()`

แก้ schema Postgres ที่ `src/auth/repositories/drizzle/schema.ts` แล้วรัน `pnpm db:generate` เพื่อสร้าง migration ใหม่ (`pnpm db:studio` เปิด Drizzle Studio)


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
- `GET /.well-known/openid-configuration` · `GET /.well-known/jwks.json`
- `GET /oauth/authorize` · `POST /oauth/token` · `POST /oauth/revoke` · `GET /oauth/userinfo` (Bearer)
- `POST /auth/register` (`username`, `email`, `password`, `profiles`, `preferredLang?`) · `POST /auth/login/password`
- `GET /auth/me` · `PATCH /auth/me` (Bearer)
- `POST /auth/webauthn/login/options` · `POST /auth/webauthn/login/verify`
- `POST /auth/webauthn/register/options` · `POST /auth/webauthn/register/verify` · `GET/DELETE /auth/webauthn/credentials` (Bearer)

Admin (ต้องมี role `admin`):

- admin กลุ่มแรกมาจาก `ADMIN_USERNAMES` ใน `.env` (ใช้ตอน start และตอน register)
- `GET /admin/users` · `PUT /admin/users/:username/roles` body `{ "roles": ["admin"] }` — ถอด admin คนสุดท้ายไม่ได้; role ตรวจจาก DB ทุก request (ถอดแล้วมีผลทันที)

Secrets (ต้องมี Bearer token) — ค่าเก็บใน Key Vault, เจ้าของ/สิทธิ์เก็บใน DB ของแอป (`secret_acls`):

- คนสร้างเป็นเจ้าของ: ดู / แก้ / ลบ / แชร์ได้ — คนอื่นเห็นแค่ชื่อ เว้นแต่เจ้าของให้สิทธิ์ `read` (ดูค่า), `write` (แก้), `delete` (ลบ)
- ชื่อซ้ำ (ไม่สนตัวพิมพ์) สร้างไม่ได้; secret ใน vault ที่ไม่ได้สร้างผ่านแอปจะไม่แสดงและยึดไม่ได้ (409)
- `GET /secrets` — ทุก secret: ชื่อ, วันที่, `owner`, `access` ของผู้เรียก (ไม่มี value)
- `GET /secrets/:name` — value (ต้องมี `read`)
- `PUT /secrets/:name` body: `{ "value": "..." }` — สร้าง (201, เป็นเจ้าของ) หรือแก้ (204, ต้องมี `write`)
- `DELETE /secrets/:name` (ต้องมี `delete`)
- `PUT /secrets/:name/owner` body `{ "username": "..." }` — โอนเจ้าของ: เจ้าของยกให้คนอื่น หรือ admin โอนให้ (admin โอนให้ตัวเองไม่ได้ และอ่านค่าไม่ได้ถ้าไม่ได้รับสิทธิ์); เจ้าของเดิมหมดสิทธิ์
- `GET /secrets/:name/grants` · `PUT /secrets/:name/grants/:username` body `{ "permissions": ["read","write","delete"] }` · `DELETE /secrets/:name/grants/:username` — เจ้าของเท่านั้น
