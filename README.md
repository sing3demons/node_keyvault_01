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

```bash
curl -X PUT http://localhost:3000/secrets/demo \
  -H "Content-Type: application/json" \
  -d '{"value":"hello-local"}'

curl http://localhost:3000/secrets/demo

curl -X DELETE http://localhost:3000/secrets/demo
```

## Run แบบ local (ไม่ใช้ docker app)

```bash
pnpm install
cp .env.example .env
docker compose up -d keyvault   # รันแค่ emulator
pnpm dev                        # API :3000 + UI (Vite) http://localhost:5173
```

## สลับไป Azure Key Vault จริง

```bash
# ใน .env ลบ block emulator (AZURE_KEYVAULT_URL, IDENTITY_*, NODE_TLS_REJECT_UNAUTHORIZED)
# แล้วใส่ AZURE_KEYVAULT_URL / AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
```

## Endpoint

- `GET /health`
- `GET /secrets` (list ชื่อ + วันที่ ไม่มี value)
- `GET /secrets/:name`
- `PUT /secrets/:name` body: `{ "value": "..." }`
- `DELETE /secrets/:name`
