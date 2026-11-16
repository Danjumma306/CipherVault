# Deliverable 3: Security Features Documentation

## 1. System Security Architecture Overview

CipherVault is engineered around defense-in-depth so that no single compromised layer (database dump, network channel, or unprivileged user account) exposes protected files.

```
Standard Users (/)                         Admin Operator (/ops-gate-7f3a)
  Username/Email + Strong Password           Google Sign-In / ADMIN_PASSKEY
        │                                          │
        └────────────────────┬─────────────────────┘
                             ▼  (TLS / HTTPS + Bearer Token)
                     Express API + Helmet
                             │
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
Auth Channel Gate     PostgreSQL RBAC & ACL    AES-256-GCM + SHA-256
(admin channel        (Owner / ACL / Role)     (RAM Encryption &
 isolation)                                     Timing-Safe Digest)
                                                     │
                                                     ▼
                                           Cloud SQL / PostgreSQL
                                            files.ciphertext (BYTEA)
```

---

## 2. Confidentiality (Data at Rest & in Transit)

### Encryption at Rest (`server/crypto.ts`)
- **Algorithm**: **AES-256-GCM** (Galois/Counter Mode, NIST SP 800-38D), providing authenticated encryption.
- **Per-File Key Derivation**: Rather than encrypting every file directly with a static key, CipherVault generates a fresh **128-bit random salt** per upload and derives a unique **256-bit Data Encryption Key (DEK)** using **HKDF-SHA256** (`crypto.hkdfSync`) bound to `VAULT_MASTER_KEY`.
- **Unique Initialization Vectors (IV)**: Every upload generates a cryptographically random **96-bit (12-byte) IV** via `crypto.randomBytes(12)`.
- **Zero Plaintext in Storage**: Multer stores uploaded payloads strictly in RAM (`multer.memoryStorage()`). Plaintext buffers are encrypted in memory before Drizzle ORM persists the ciphertext `Buffer` into PostgreSQL `files.ciphertext` (`bytea`).

### Confidentiality in Transit & Client Session Hygiene
- **TLS / HTTPS**: Hosted Cloud Run deployments terminate TLS 1.2/1.3 at ingress, and Cloud SQL connections run over the encrypted Cloud SQL Auth Proxy Unix socket.
- **HTTP Hardening (`server.ts`)**: `helmet` enforces strict HTTP response headers (`X-Content-Type-Options: nosniff`, `Cache-Control: no-store` on downloads).
- **In-Memory Client Tokens (`src/App.tsx`)**: Authentication tokens are stored strictly in React memory rather than `localStorage`.

---

## 3. Integrity (Tamper Detection)

CipherVault verifies file integrity at **two independent cryptographic layers** before returning a single decrypted byte (`verifyAndDecryptBuffer` in `server/crypto.ts`):

1. **SHA-256 Digest Pre-Check**:
   - Computes `SHA-256(ciphertext)` on upload and stores it in `files.sha256_hash`.
   - Recomputes `SHA-256(ciphertext)` on download and compares via **`crypto.timingSafeEqual`**. Any mismatch aborts with **HTTP `422 Unprocessable Entity` (`INTEGRITY_VERIFICATION_FAILED`)**.
2. **AES-256-GCM 128-Bit Authentication Tag**:
   - `decipher.setAuthTag()` verifies the 16-byte GCM tag before returning decrypted bytes.

---

## 4. Authentication & Authorization

### Strong Password Policy, Hashing & Email OTP Verification
- **Client & Server Password Enforcement**: Public registration requires **12+ characters**, uppercase, lowercase, digit, special symbol, and excludes the user's username or email local-part.
- **Password Hashing**: Salted and hashed with **bcrypt** (`bcryptjs`, cost factor **12**).
- **Email OTP Verification (`server/mailer.ts`, `server/routes.ts`)**: New accounts start with `email_verified = false` and receive a cryptographically random 6-digit OTP (`crypto.randomInt`) valid for 10 minutes. Only the **HMAC-SHA256** digest (`otp_hash`) is stored in PostgreSQL and verified with `crypto.timingSafeEqual` (capped at 5 attempts). Standard `POST /api/auth/login` denies unverified accounts (`403 EMAIL_NOT_VERIFIED`). After verifying the OTP, users are returned to Sign In to authenticate with their password and obtain an in-memory JWT.

### Admin Channel Isolation & Obscured Operator Gate
- Standard password login (`POST /api/auth/login`) explicitly rejects `admin` accounts and issues tokens stamped with `authMethod: 'password'`.
- Public registration rejects `ADMIN_EMAIL` (`403 Forbidden`).
- The administrator authenticates exclusively through the unlinked `/ops-gate-7f3a` gate using **Google Sign-In** (Firebase ID token strictly matched against `ADMIN_EMAIL` on the server) or a timing-safe `ADMIN_PASSKEY` in local/offline environments (`authMethod: 'operator'`).
- `authenticateJWT` rejects any `role === 'admin'` session that did not originate from the verified operator channel.

### Authorization: RBAC + Per-File ACLs
- **RBAC**: `admin` manages non-admin user roles (`member` / `viewer`) and views system-wide `audit_logs`; `member` uploads, shares, and downloads authorized files; `viewer` is blocked (`403`) from uploading.
- **Account & Artifact Isolation**: `GET /api/files`, `GET /api/files/:id/download`, and `GET /api/inspector/:id` enforce ownership or an explicit row in `access_control_lists` (`403 Forbidden` otherwise). Non-admins cannot view other users' emails or inspect artifacts they do not have access to.
