# Deliverable 5: Live Class Presentation & Demonstration Script

**Estimated Duration:** 5–7 minutes  
**Objective:** Prove live that CipherVault enforces **confidentiality** (unreadable ciphertext in PostgreSQL), **integrity** (SHA-256 + AES-GCM tamper rejection), **strong credential policy**, and **strict privilege separation** (obscured Admin Operator Gate vs. standard user accounts + per-file ACLs).

---

## Preparation Before Presenting

1. Ensure the application is running (`npm run dev` locally or via your deployed Cloud Run URL).
2. Have two standard browser profiles or incognito windows ready (User A and User B), plus the obscured administrator URL (`/ops-gate-7f3a`) ready in a separate tab.

---

## Step 1: Register Two Standard Users, Password Policy & Email OTP (1 min)

- **Action:** On the standard sign-in page (`/`), switch to **Create Account**.
- **Talking Point:** *"Notice there are no demo shortcuts, and attempting a weak password like `Password123` keeps registration disabled until all six criteria—12+ characters, upper, lower, digit, symbol, and no username/email match—pass on both client and server."*
- **Action:** Register **User A** (e.g., `alice_sec`), enter the 6-digit **Email OTP** code on the verification screen, confirm redirection back to **Sign In**, and log in with User A's credentials. Repeat in a second browser window for **User B** (e.g., `bob_sec`).

---

## Step 2: Upload & Inspect Unreadable Ciphertext (1.5 min)

- **Action:** As **User A**, upload a readable plain-text file (e.g., `grades_report.txt`) in **My Vault**.
- **Action:** Click **Inspect** to open the **Security Inspector**.
- **Talking Point:** *"Plaintext is held only in server RAM during upload, encrypted with AES-256-GCM using a fresh 96-bit IV and per-file HKDF key, and stored in PostgreSQL as unreadable `BYTEA` ciphertext."*
- **Action:** Click **Test Verified Download** to confirm `HTTP 200 OK` and clean decryption for the owner.

---

## Step 3: Prove Strict Account Isolation & Per-File ACL Sharing (1.5 min)

- **Action:** In **User B**'s window, open **My Vault**, **Shared With Me**, and **Security Inspector**.
- **Talking Point:** *"User B sees zero files and cannot inspect User A's encrypted artifacts or access the Admin account. Even if User B attempts to fetch User A's file ID directly via API, the server blocks it with `HTTP 403 Forbidden`."*
- **Action:** In **User A**'s window, click **Share**, select **User B**, grant `read` access, and refresh **User B**'s **Shared With Me** view to verify authorized download succeeds.

---

## Step 4: Demonstrate Storage Tampering Detection (1 min)

- **Action:** As **User A**, open **Security Inspector** and click **Simulate 1-Byte Disk Tamper**.
- **Action:** Click **Test Verified Download**.
- **Expected Result:** Red **HTTP 422 — Integrity Verification Failure** banner (`SHA-256 integrity verification failed`).
- **Action:** Click **Restore Original Ciphertext** to verify clean recovery.

---

## Step 5: Demonstrate Obscured Admin Operator Gate & RBAC Controls (1 min)

- **Action:** Point out that on `/`, trying to log in with the administrator email via password fails, and no admin link exists anywhere in the UI.
- **Action:** Navigate directly to `/ops-gate-7f3a` and click **Authenticate with Google** (as `osmanp999@gmail.com`)—or **Offline Operator Passkey** if running locally without Firebase Authorized Domains.
- **Talking Point:** *"The administrator authenticates through an isolated operator channel verified against the configured `ADMIN_EMAIL` on the server."*
- **Action:** Open **Audit Log** to inspect the system-wide cryptographic audit ledger and optionally demote **User B** to `viewer` in the **RBAC Role Directory** to show `viewer` upload prevention live.
