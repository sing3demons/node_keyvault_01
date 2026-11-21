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
- Mailpit (กล่องรับ email ทดสอบ — รหัสยืนยัน): `http://localhost:8025`

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
docker compose up -d keyvault mongo mailpit   # emulator + MongoDB (หรือ postgres ถ้า AUTH_DB=postgres) + Mailpit
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

**OAuth clients** (เก็บใน DB — จัดการโดย admin ที่ปุ่ม "Clients" หรือ `/admin/clients`)

- metadata ตาม RFC 7591: `client_id`, `client_name`, `redirect_uris` (ตรงทุกตัวอักษร; https, http เฉพาะ localhost, หรือ private-use scheme แบบ `com.example.app:/cb` ตาม RFC 8252), `token_endpoint_auth_method`, `grant_types`, `scope`, `client_uri`, `initiate_login_uri` (OIDC)
- ชนิด client: `none` = public (SPA / mobile, ใช้ PKCE อย่างเดียว) · `client_secret_basic` (default ตาม RFC 7591) / `client_secret_post` = confidential — secret แสดงครั้งเดียวตอนสร้าง/rotate, DB เก็บแค่ SHA-256
- ตั้งค่าต่อ client (แทน env เดิม): `access_token_lifetime`, `refresh_token_lifetime`, `id_token_lifetime` (ไม่เกิน `OIDC_RETIRED_KEY_GRACE_SEC`), `email_verification` (`code` | `link`); refresh token ออกให้เฉพาะ client ที่มี grant `refresh_token`; scope ที่ขอต้องอยู่ใน `scope` ของ client (ไม่ส่ง scope = ใช้ของ client)
- `/oauth/token` และ `/oauth/revoke` ต้องยืนยันตัว client ตามวิธีที่ลงทะเบียน (RFC 6749 §2.3, RFC 7009); revoke ได้เฉพาะ token ของตัวเอง
- ลบ client = revoke token ของมันทั้งหมด (RFC 7592); ลบ client ที่ตัวเอง login อยู่ไม่ได้
- **Master credential** — `MASTER_CREDENTIALS` = base64(`username:password`) (password ≥ 16 ตัว) ใช้จัดการ client ได้โดยไม่ต้องมี user admin: เปิดหน้า `/manage` แล้ว login ด้วย username/password นั้น หรือเรียก API ด้วย `Authorization: Basic $MASTER_CREDENTIALS`; จัดการได้เฉพาะ `/admin/clients` (ไม่รวม users / secrets); ไม่ตั้ง = ปิด, ค่าผิดรูปแบบ = server ไม่ start
  ```bash
  printf 'master:%s' "$(openssl rand -base64 24)" | base64   # ใส่ใน MASTER_CREDENTIALS
  curl -H "Authorization: Basic $MASTER_CREDENTIALS" http://localhost:3000/admin/clients
  ```
- start ครั้งแรกสร้าง client `keyvault-web` (public) ของ UI ให้เอง: redirect `<WEBAUTHN_ORIGINS>/callback`, `initiate_login_uri` = origin แรก — env เก่า (`OAUTH_CLIENT_ID`, `OAUTH_REDIRECT_URIS`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL`, `ID_TOKEN_TTL`, `EMAIL_VERIFICATION`) ยังถูกอ่านเป็นค่าตั้งต้นครั้งนั้นครั้งเดียว หลังจากนั้นแก้ใน Clients

**ยืนยัน email (รหัส 6 หลัก หรือ link — ตั้งที่ client)**

- `email_verification` ของ client ที่ user กำลัง login เข้า: `code` — รหัส 6 หลัก · `link` — link `<origin ของหน้า login>/verify-email?id=…&token=…` (token 256-bit, ใช้ครั้งเดียว; origin ต้องอยู่ใน `WEBAUTHN_ORIGINS`) ต้องกดปุ่มในหน้านั้นก่อน (กัน mail scanner); ชื่อใน email = `client_name`
  - link สำหรับ login (`&signin=1`): **login ใน browser ที่เปิด link** — server เก็บ link ไว้ใน cookie แล้วส่ง browser ไป `initiate_login_uri` ของ client (OIDC Third-Party Initiated Login) → client เริ่ม `/oauth/authorize` ใหม่ (PKCE/state ของมันเอง) → หน้า login เรียก `POST /auth/email/link/resume` → redirect กลับ client พร้อม code; ถ้า client ไม่มี `initiate_login_uri` จะจบ request เดิมแทน (เหมาะกับ client ฝั่ง server ที่เก็บ state ใน cookie); link ใช้กับ client อื่นไม่ได้
  - link ยืนยัน email จากหน้า Account: ยืนยันเฉยๆ ไม่ login; dialog ที่เปิดค้างรู้เองจาก poll `POST /auth/email/status`
  - challenge ที่ส่งไปแล้วใช้วิธีเดิมต่อแม้เปลี่ยนค่า client

- สมัครสมาชิก → ส่งรหัสไปที่ email → กรอกรหัสในหน้า login แล้วเข้าระบบเลย (`Account.emailVerified`, claim `email_verified`)
- login ด้วย **email + password** → ต้องกรอกรหัสที่ส่งไป email ทุกครั้ง; login ด้วย **username + password** → ไม่ต้อง ยกเว้น email ยังไม่ได้ยืนยัน (เช่น บัญชีเก่า) จะให้ยืนยันก่อน
- เปลี่ยน email ใน Account → กลับเป็นยังไม่ยืนยัน กด "Send verification code" เพื่อยืนยันใหม่
- รหัสเก็บเป็น SHA-256 เท่านั้น, อายุ `EMAIL_CODE_TTL` (10 นาที), ผิดได้ `EMAIL_CODE_MAX_ATTEMPTS` ครั้ง, ส่งซ้ำได้ทุก `EMAIL_CODE_RESEND_COOLDOWN` วินาที
- ส่งผ่าน SMTP (`SMTP_URL`, `MAIL_FROM`); ไม่ตั้ง `SMTP_URL` = พิมพ์รหัสลง log ของ server (dev เท่านั้น)

**Devices (อุปกรณ์ที่เคย login)**

- ทุกครั้งที่ login สำเร็จ (password / passkey / รหัส email) จะบันทึกอุปกรณ์: browser + OS (จาก User-Agent), IP, วันที่ login ครั้งแรก/ล่าสุด, ใช้งานล่าสุด (อัปเดตตอน refresh token), วิธี login, จำนวนครั้ง
- จำอุปกรณ์ด้วย cookie `kv_device` (httpOnly, path `/auth`, ค่าสุ่ม เก็บใน DB เป็น hash) — token ที่ออกให้ผูกกับอุปกรณ์นั้น
- ปุ่ม "Devices" ใน UI: ดูรายการ, "Sign out" (revoke token ของอุปกรณ์นั้น แต่เก็บประวัติไว้), ถังขยะ (sign out + ลบออกจากรายการ); อุปกรณ์ที่ใช้อยู่ให้ใช้ Log out
- อยู่หลัง reverse proxy ให้ตั้ง `TRUST_PROXY=true` เพื่อให้ IP มาจาก `X-Forwarded-For`

โค้ด auth ทั้งหมดคุยผ่าน `AuthRepository` ([src/auth/repository.ts](src/auth/repository.ts)) — เพิ่ม DB ใหม่ได้โดย implement interface นี้ใน `src/auth/repositories/` แล้วเพิ่มใน `createAuthRepository()`

แก้ schema Postgres ที่ `src/auth/repositories/drizzle/schema.ts` แล้วรัน `pnpm db:generate` เพื่อสร้าง migration ใหม่ (`pnpm db:studio` เปิด Drizzle Studio)


- **OAuth2 Authorization Code + PKCE (S256)** — ทุก client ต้องใช้ PKCE; React UI เป็น public client `keyvault-web`
- **Password** — hash ด้วย argon2id
- **Passkey (WebAuthn)** — ใช้ fido2-lib แบบ discoverable credential (sign-in โดยไม่ต้องพิมพ์ username)
- **Token แบบ opaque** — access token (15 นาที) + refresh token (30 วัน, rotation + reuse detection) เก็บใน Mongo เป็น SHA-256 hash เท่านั้น

Flow: UI → `GET /oauth/authorize` → redirect ไป `/login?request_id=…` → login ด้วย password หรือ passkey → redirect กลับ `/callback?code=…` → UI แลก code ที่ `POST /oauth/token` ด้วย `code_verifier`

เพิ่ม passkey ได้จากปุ่ม "Add passkey" หลัง login (ทดสอบบน Chrome ได้ด้วย DevTools → More tools → WebAuthn → virtual authenticator)

ตั้งค่าใน `.env` (เฉพาะของทั้ง server): `MONGO_URL`, `MONGO_DB`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS`, `OIDC_ISSUER`, `SMTP_URL`, … (ดู `.env.example`) — ค่าของแต่ละแอปอยู่ที่ client
— `WEBAUTHN_ORIGINS` ต้องตรงกับ origin ที่เปิดหน้า login จริง (dev: `:5173`, build: port ของ API)

## Endpoint

- `GET /health`
- `GET /.well-known/openid-configuration` · `GET /.well-known/jwks.json`
- `GET /oauth/authorize` · `POST /oauth/token` · `POST /oauth/revoke` · `GET /oauth/userinfo` (Bearer)
- `POST /auth/register` (`username`, `email`, `password`, `profiles`, `preferredLang?`, `request_id?`) → account + `verification` (ส่งรหัสไป email แล้ว)
- `POST /auth/login/password` (`username` = username หรือ email) → `{ redirect }` หรือ `{ verify }` (ต้องกรอกรหัสจาก email ต่อ)
- `POST /auth/email/verify` (`challengeId`, `code`, `request_id?`) → `{ redirect }` (ขั้น login) หรือ `{ verified: true }` · `POST /auth/email/resend` (`challengeId`)
- client แบบ link: `POST /auth/email/link` (`challengeId`, `token`, `request_id?`) → `{ verified }` / `{ continue }` (+ cookie) / `{ redirect }` · `POST /auth/email/link/resume` (`request_id`) → `{ redirect }` · `POST /auth/email/status` (`challengeId`) → `{ pending }` / `{ verified }`
- `GET /auth/me` · `PATCH /auth/me` · `POST /auth/me/email/verification` (Bearer)
- `GET /auth/me/devices` · `POST /auth/me/devices/:id/sign-out` · `DELETE /auth/me/devices/:id` (Bearer)
- `POST /auth/webauthn/login/options` · `POST /auth/webauthn/login/verify`
- `POST /auth/webauthn/register/options` · `POST /auth/webauthn/register/verify` · `GET/DELETE /auth/webauthn/credentials` (Bearer)

Admin (ต้องมี role `admin`):

- admin กลุ่มแรกมาจาก `ADMIN_USERNAMES` ใน `.env` (ใช้ตอน start และตอน register)
- `GET /admin/users` · `PUT /admin/users/:username/roles` body `{ "roles": ["admin"] }` — ถอด admin คนสุดท้ายไม่ได้; role ตรวจจาก DB ทุก request (ถอดแล้วมีผลทันที)
- `GET/POST /admin/clients` · `GET/PUT/DELETE /admin/clients/:id` · `POST /admin/clients/:id/secret` (rotate) — body เป็น client metadata (RFC 7591), PUT ส่งครบทุก field (RFC 7592)

```bash
curl -X POST http://localhost:3000/admin/clients -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"client_name":"Billing","redirect_uris":["https://billing.example.com/cb"],"scope":"openid email",
       "grant_types":["authorization_code","refresh_token"],"email_verification":"link",
       "initiate_login_uri":"https://billing.example.com/login","access_token_lifetime":600}'
# -> 201 { "client_id": "...", "client_secret": "...", "client_secret_expires_at": 0, ... }
```

Secrets (ต้องมี Bearer token) — ค่าเก็บใน Key Vault, เจ้าของ/สิทธิ์เก็บใน DB ของแอป (`secret_acls`):

- คนสร้างเป็นเจ้าของ: ดู / แก้ / ลบ / แชร์ได้ — คนอื่นเห็นแค่ชื่อ เว้นแต่เจ้าของให้สิทธิ์ `read` (ดูค่า), `write` (แก้), `delete` (ลบ)
- ชื่อซ้ำ (ไม่สนตัวพิมพ์) สร้างไม่ได้; secret ใน vault ที่ไม่ได้สร้างผ่านแอปจะไม่แสดงและยึดไม่ได้ (409)
- `GET /secrets` — ทุก secret: ชื่อ, วันที่, `owner`, `access` ของผู้เรียก (ไม่มี value)
- `GET /secrets/:name` — value (ต้องมี `read`)
- `PUT /secrets/:name` body: `{ "value": "..." }` — สร้าง (201, เป็นเจ้าของ) หรือแก้ (204, ต้องมี `write`)
- `DELETE /secrets/:name` (ต้องมี `delete`)
- `PUT /secrets/:name/owner` body `{ "username": "..." }` — โอนเจ้าของ: เจ้าของยกให้คนอื่น หรือ admin โอนให้ (admin โอนให้ตัวเองไม่ได้ และอ่านค่าไม่ได้ถ้าไม่ได้รับสิทธิ์); เจ้าของเดิมหมดสิทธิ์
- `GET /secrets/:name/grants` · `PUT /secrets/:name/grants/:username` body `{ "permissions": ["read","write","delete"] }` · `DELETE /secrets/:name/grants/:username` — เจ้าของเท่านั้น
