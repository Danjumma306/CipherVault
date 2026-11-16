# CipherVault — Secure File-Sharing Application

CipherVault is a full-stack secure file-sharing system built for university computer security coursework. It enforces **confidentiality**, **integrity**, and **least-privilege access control** across the entire request lifecycle using Node.js, Express, **PostgreSQL** (Cloud SQL in production, or local PostgreSQL on your device), Drizzle ORM, **AES-256-GCM**, HKDF-SHA256, SHA-256 digests, bcrypt password hashing, Firebase Google Sign-In (for the isolated administrator operator gate), and signed JSON Web Tokens (JWT) with Role-Based Access Control (RBAC) and per-file Access Control Lists (ACLs).

---

## Class Deliverables Index

| Deliverable | Description | Location |
| :--- | :--- | :--- |
| **Deliverable 1** | Functional Application Code (Express API, Crypto Engine, Auth/RBAC, Drizzle PostgreSQL Persistence) | `server/crypto.ts`, `server/auth.ts`, `server/routes.ts`, `src/db/*` |
| **Deliverable 2** | Database Design (PostgreSQL DDL Schema for Users, Encrypted `BYTEA` Files, ACLs, Audit Logs) | [`docs/DATABASE_DESIGN.sql`](./docs/DATABASE_DESIGN.sql) |
| **Deliverable 3** | Security Features Documentation (Confidentiality, Integrity, AuthN & AuthZ) | [`docs/SECURITY_ARCHITECTURE.md`](./docs/SECURITY_ARCHITECTURE.md) |
| **Deliverable 4** | End-User Manual (Registration, Upload, Secure Sharing, Verified Download) | [`docs/USER_MANUAL.md`](./docs/USER_MANUAL.md) |
| **Deliverable 5** | Live Class Presentation & Demonstration Script | [`docs/DEMO_SCRIPT.md`](./docs/DEMO_SCRIPT.md) |

---

## Authentication & Privilege Separation

- **Standard Users (`/`):** Register and sign in using a username/email and a **strong password** (enforced on both client and server: minimum 12 characters, uppercase, lowercase, number, special character, and excluding username/email substrings). Passwords are hashed with `bcryptjs` (cost factor 12). New accounts must verify their email address via a **6-digit Email OTP** (HMAC-SHA256 hashed with 10-minute expiry and 5-attempt limit) before returning to the Sign In form to obtain a short-lived in-memory JWT (`authMethod: 'password'`).
- **Administrator Operator Gate (`/ops-gate-7f3a`):** Unlinked from the public UI and inaccessible via standard password login (`POST /api/auth/login` rejects admin accounts). The designated administrator (`ADMIN_EMAIL`) authenticates via **Google Sign-In** (Firebase ID token verified server-side) or—for offline/local setups—an `ADMIN_PASSKEY` configured in `.env`.
- **Account & Artifact Isolation:** Users only see their own files and files explicitly shared with them via `access_control_lists`. Non-admins cannot inspect other users' artifacts or discover administrator accounts.

---

## Running Locally on Your Own Device

### Prerequisites
- **Node.js 20+** and `npm`
- **PostgreSQL 15+** (local server or Docker)

### Step 1: Start a Local PostgreSQL Database

**Option A — Docker:**
```bash
docker run --name ciphervault-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=localdevpassword \
  -e POSTGRES_DB=ciphervault \
  -p 5432:5432 \
  -d postgres:16
```

**Option B — Native PostgreSQL:**
```bash
psql -U postgres -c "CREATE DATABASE ciphervault;"
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Create `.env`
```bash
cp .env.example .env
```
Generate cryptographic secrets and an offline operator passkey:
```bash
node -e "const c=require('crypto'); console.log('JWT_SECRET=' + c.randomBytes(32).toString('hex')); console.log('VAULT_MASTER_KEY=' + c.randomBytes(32).toString('hex')); console.log('ADMIN_PASSKEY=' + c.randomBytes(24).toString('hex'));"
```
Configure `.env`:
```env
SQL_HOST="localhost"
SQL_PORT="5432"
SQL_DB_NAME="ciphervault"
SQL_USER="postgres"
SQL_PASSWORD="localdevpassword"
SQL_ADMIN_USER="postgres"
SQL_ADMIN_PASSWORD="localdevpassword"

ADMIN_EMAIL="osmanp999@gmail.com"
ADMIN_PASSKEY="<paste-generated-passkey>"
JWT_SECRET="<paste-64-hex-chars>"
VAULT_MASTER_KEY="<paste-64-hex-chars>"

# Free SMTP for real Email OTP delivery (Gmail App Password — no paid plan required)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="465"
SMTP_SECURE="true"
SMTP_USER="osmanp999@gmail.com"
SMTP_PASS="<your-16-char-google-app-password>"
SMTP_FROM="CipherVault <osmanp999@gmail.com>"
```

### Step 4: Push the Schema to PostgreSQL
```bash
npx drizzle-kit push --config=src/db/drizzle.config.ts
```

### Step 5: Start the Application
```bash
npm run dev
```
- Standard user portal: `http://localhost:3000/`
- Obscured administrator gate: `http://localhost:3000/ops-gate-7f3a` (use **Offline Operator Passkey** locally if `localhost` is not added to Firebase Authorized Domains, or **Authenticate with Google** once authorized).

---

## Verification & Production Build
```bash
npm run lint
npm run build
```
