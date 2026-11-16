# Deliverable 4: CipherVault End-User Manual

Welcome to **CipherVault**, a secure file-sharing console that encrypts your files automatically before saving them to PostgreSQL storage and restricts downloads to explicitly authorized recipients.

---

## 1. Creating an Account, Email OTP Verification & Signing In

1. Open CipherVault in your browser.
2. Select **Create Account** on the authentication panel.
3. Enter a **Username** (at least 3 characters), **Email Address**, and a **Strong Password** meeting all six checked requirements:
   - At least **12 characters**
   - At least one **uppercase letter** (`A–Z`)
   - At least one **lowercase letter** (`a–z`)
   - At least one **number** (`0–9`)
   - At least one **special character** (e.g., `!@#$%^&*`)
   - Does **not** contain your username or email prefix
4. Once the Password Strength indicator reaches **Strong**, click **Create Account & Send Email OTP**.
   - Your password is salted and hashed on the server using bcrypt (cost factor 12) and a 6-digit verification code is dispatched to your email address (valid for 10 minutes).
5. Enter the 6-digit verification code and click **Verify Email**.
   - Once verified, CipherVault automatically returns you to the **Sign In** panel.
6. Sign in with your verified username or email and password, and click **Sign In & Issue JWT** to enter your encrypted vault.

---

## 2. Uploading & Encrypting a File

1. Navigate to **My Vault** in the left sidebar.
2. Either drag and drop a file onto the upload dropzone or click **Upload & Encrypt File** (maximum 15 MB per file).
3. CipherVault immediately encrypts the file in server memory using **AES-256-GCM**, records its **SHA-256** integrity digest and 96-bit IV, and persists only the unreadable ciphertext (`bytea`) inside PostgreSQL.
4. Your file appears in the vault table with a **Verified** integrity status.

> **Note:** Accounts assigned the `viewer` role cannot upload files and will see an RBAC restriction notice.

---

## 3. Sharing a File Securely with Another User

1. In **My Vault**, locate the file you want to share and click **Share**.
2. In the **Access Control List** drawer:
   - Choose the **Recipient Account** from the dropdown menu.
   - Select the **Permission Level** (`read` to allow verification and download, or `write` for collaborator status).
   - Click **Grant Access**.
3. The recipient now appears under **Authorized Recipients**. To remove access at any time, click the trash icon next to their name to revoke their ACL entry immediately.

---

## 4. Downloading & Verifying a Shared File

1. Navigate to **My Vault** (for files you own) or **Shared With Me** (for files shared with you by another user).
2. Click **Download** on the desired row.
3. Before sending the file to your browser, CipherVault automatically:
   - Confirms your session token is valid.
   - Checks that you are the file owner or listed in the file's **Access Control List**.
   - Verifies the stored ciphertext in PostgreSQL against its stored **SHA-256** digest and **AES-256-GCM** authentication tag.
4. Once verified, the decrypted file downloads cleanly and a confirmation banner displays the verified SHA-256 prefix. If the stored ciphertext was corrupted or altered, the download is blocked to protect you from tampered data.
