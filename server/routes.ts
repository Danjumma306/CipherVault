import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { and, asc, desc, eq, inArray, ne, or } from 'drizzle-orm';
import express, { type Response } from 'express';
import multer from 'multer';
import path from 'path';
import { db } from '../src/db/index.ts';
import { accessControlLists, auditLogs, files, users } from '../src/db/schema.ts';
import {
  ensureAdminUserRecord,
  findUserByIdentifier,
  getAdminEmail,
  isAdminEmail,
  logAuditEvent,
  type UserRole,
} from '../src/db/users.ts';
import { adminAuth } from '../src/lib/firebase-admin.ts';
import { authenticateJWT, type AuthenticatedRequest, issueToken, requireRole } from './auth.ts';
import {
  computeSha256,
  encryptBuffer,
  IntegrityError,
  JWT_SECRET,
  verifyAndDecryptBuffer,
} from './crypto.ts';
import { sendOtpVerificationEmail } from './mailer.ts';

const router = express.Router();

// Store uploads strictly in memory buffer so plaintext NEVER touches disk unencrypted
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
});

function validatePasswordStrength(
  password: string,
  username: string,
  email: string,
): string | null {
  if (password.length < 12) {
    return 'Password must be at least 12 characters long.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must include at least one uppercase letter.';
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must include at least one lowercase letter.';
  }
  if (!/[0-9]/.test(password)) {
    return 'Password must include at least one number.';
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'Password must include at least one special character (e.g. !@#$%^&*).';
  }
  const lower = password.toLowerCase();
  const emailLocal = email.split('@')[0]?.toLowerCase() ?? '';
  if (username.length >= 3 && lower.includes(username.toLowerCase())) {
    return 'Password cannot contain your username.';
  }
  if (emailLocal.length >= 3 && lower.includes(emailLocal)) {
    return 'Password cannot contain your email address.';
  }
  return null;
}

const OTP_EXPIRY_MINUTES = 10;
const MAX_OTP_ATTEMPTS = 5;

function generateOtpCode(): string {
  return crypto.randomInt(100000, 1000000).toString();
}

function createOtpHash(email: string, otp: string): string {
  return crypto.createHmac('sha256', JWT_SECRET).update(`${email}:${otp}`).digest('hex');
}

function verifyOtpHash(email: string, otp: string, storedHash: string): boolean {
  const expectedHex = createOtpHash(email, otp);
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  const actualBuf = Buffer.from(storedHash, 'hex');
  if (expectedBuf.length !== actualBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuf, actualBuf);
}

// -----------------------------------------------------------------------------
// Standard User Authentication Routes (Non-Admin Only)
// -----------------------------------------------------------------------------

router.post('/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body ?? {};
    const cleanUsername = String(username ?? '').trim().toLowerCase();
    const cleanEmail = String(email ?? '').trim().toLowerCase();
    const rawPassword = String(password ?? '');

    if (!cleanUsername || cleanUsername.length < 3 || !/^[a-z0-9_.-]+$/.test(cleanUsername)) {
      res.status(400).json({ error: 'Username must be at least 3 characters (letters, numbers, ., _, -).' });
      return;
    }
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      res.status(400).json({ error: 'Provide a valid email address.' });
      return;
    }
    if (isAdminEmail(cleanEmail)) {
      res.status(403).json({ error: 'This email address is reserved and cannot be registered publicly.' });
      return;
    }

    const strengthError = validatePasswordStrength(rawPassword, cleanUsername, cleanEmail);
    if (strengthError) {
      res.status(400).json({ error: strengthError });
      return;
    }

    const matches = await db
      .select({
        id: users.id,
        username: users.username,
        email: users.email,
        emailVerified: users.emailVerified,
      })
      .from(users)
      .where(or(eq(users.username, cleanUsername), eq(users.email, cleanEmail)));

    const byEmail = matches.find((row) => row.email === cleanEmail);
    const byUsername = matches.find((row) => row.username === cleanUsername);

    if (byEmail?.emailVerified) {
      res.status(409).json({ error: 'An account with this email is already registered and verified.' });
      return;
    }
    if (byUsername && byUsername.email !== cleanEmail) {
      res.status(409).json({ error: 'Username is already taken.' });
      return;
    }

    const passwordHash = await bcrypt.hash(rawPassword, 12);
    const otp = generateOtpCode();
    const otpHash = createOtpHash(cleanEmail, otp);
    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    let userId: string;
    if (byEmail) {
      userId = byEmail.id;
      await db
        .update(users)
        .set({
          username: cleanUsername,
          passwordHash,
          otpHash,
          otpExpiresAt,
          otpAttempts: 0,
        })
        .where(eq(users.id, userId));
    } else {
      userId = crypto.randomUUID();
      await db.insert(users).values({
        id: userId,
        uid: null,
        username: cleanUsername,
        email: cleanEmail,
        passwordHash,
        role: 'member',
        emailVerified: false,
        otpHash,
        otpExpiresAt,
        otpAttempts: 0,
      });
    }

    const mailResult = await sendOtpVerificationEmail({
      toEmail: cleanEmail,
      username: cleanUsername,
      otp,
      expiresMinutes: OTP_EXPIRY_MINUTES,
    });

    await logAuditEvent({
      actorId: userId,
      actorUsername: cleanUsername,
      action: 'REGISTER_OTP_SENT',
      status: 'success',
      detail: `Created pending account (${cleanEmail}) and dispatched 6-digit verification OTP (${mailResult.delivery}).`,
    });

    res.status(201).json({
      requiresVerification: true,
      email: cleanEmail,
      expiresInMinutes: OTP_EXPIRY_MINUTES,
      delivery: mailResult.delivery,
      previewUrl: mailResult.previewUrl,
      devOtp: mailResult.devOtp,
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Registration failed due to a server error.',
    });
  }
});

router.post('/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body ?? {};
    const cleanEmail = String(email ?? '').trim().toLowerCase();
    const cleanOtp = String(otp ?? '').trim();

    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      res.status(400).json({ error: 'Provide a valid email address.' });
      return;
    }
    if (!/^\d{6}$/.test(cleanOtp)) {
      res.status(400).json({ error: 'Enter the 6-digit numeric verification code.' });
      return;
    }

    const rows = await db
      .select()
      .from(users)
      .where(eq(users.email, cleanEmail))
      .limit(1);

    const userRow = rows[0];
    if (!userRow || userRow.role === 'admin' || isAdminEmail(userRow.email)) {
      res.status(404).json({ error: 'No pending verification found for this email address.' });
      return;
    }

    if (userRow.emailVerified) {
      res.json({
        verified: true,
        email: userRow.email,
        message: 'Email address is already verified. Please sign in.',
      });
      return;
    }

    if (!userRow.otpHash || !userRow.otpExpiresAt) {
      res.status(400).json({ error: 'No active verification code found. Request a new code.' });
      return;
    }

    if (userRow.otpAttempts >= MAX_OTP_ATTEMPTS) {
      res.status(429).json({
        error: 'Maximum verification attempts exceeded. Request a new verification code.',
      });
      return;
    }

    if (userRow.otpExpiresAt.getTime() < Date.now()) {
      res.status(400).json({ error: 'Verification code has expired. Request a new code.' });
      return;
    }

    if (!verifyOtpHash(cleanEmail, cleanOtp, userRow.otpHash)) {
      const nextAttempts = userRow.otpAttempts + 1;
      await db
        .update(users)
        .set({ otpAttempts: nextAttempts })
        .where(eq(users.id, userRow.id));

      await logAuditEvent({
        actorId: userRow.id,
        actorUsername: userRow.username,
        action: 'OTP_VERIFY_FAILED',
        status: 'denied',
        detail: `Invalid email OTP code entered (${nextAttempts}/${MAX_OTP_ATTEMPTS} attempts).`,
      });

      const remaining = Math.max(0, MAX_OTP_ATTEMPTS - nextAttempts);
      res.status(400).json({
        error:
          remaining > 0
            ? `Invalid verification code. ${remaining} attempt(s) remaining.`
            : 'Invalid verification code. Maximum attempts reached; please request a new code.',
      });
      return;
    }

    await db
      .update(users)
      .set({
        emailVerified: true,
        otpHash: null,
        otpExpiresAt: null,
        otpAttempts: 0,
      })
      .where(eq(users.id, userRow.id));

    await logAuditEvent({
      actorId: userRow.id,
      actorUsername: userRow.username,
      action: 'EMAIL_VERIFIED',
      status: 'success',
      detail: `Email address (${userRow.email}) verified via 6-digit OTP; account ready for sign-in.`,
    });

    res.json({
      verified: true,
      email: userRow.email,
      message: 'Email verified successfully. Please sign in to access your vault.',
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'Failed to verify email code.' });
  }
});

router.post('/auth/resend-otp', async (req, res) => {
  try {
    const { email } = req.body ?? {};
    const cleanEmail = String(email ?? '').trim().toLowerCase();

    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      res.status(400).json({ error: 'Provide a valid email address.' });
      return;
    }

    const rows = await db
      .select()
      .from(users)
      .where(eq(users.email, cleanEmail))
      .limit(1);

    const userRow = rows[0];
    if (!userRow || userRow.role === 'admin' || isAdminEmail(userRow.email)) {
      res.status(404).json({ error: 'Account not found.' });
      return;
    }

    if (userRow.emailVerified) {
      res.status(400).json({ error: 'Email address is already verified. Please sign in.' });
      return;
    }

    const otp = generateOtpCode();
    const otpHash = createOtpHash(cleanEmail, otp);
    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await db
      .update(users)
      .set({
        otpHash,
        otpExpiresAt,
        otpAttempts: 0,
      })
      .where(eq(users.id, userRow.id));

    const mailResult = await sendOtpVerificationEmail({
      toEmail: cleanEmail,
      username: userRow.username,
      otp,
      expiresMinutes: OTP_EXPIRY_MINUTES,
    });

    await logAuditEvent({
      actorId: userRow.id,
      actorUsername: userRow.username,
      action: 'OTP_RESENT',
      status: 'success',
      detail: `Dispatched fresh 6-digit email verification code (${mailResult.delivery}).`,
    });

    res.json({
      requiresVerification: true,
      email: cleanEmail,
      expiresInMinutes: OTP_EXPIRY_MINUTES,
      delivery: mailResult.delivery,
      previewUrl: mailResult.previewUrl,
      devOtp: mailResult.devOtp,
    });
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Failed to resend verification code.',
    });
  }
});

router.post('/auth/login', async (req, res) => {
  try {
    const { identifier, email, password } = req.body ?? {};
    const lookup = String(identifier ?? email ?? '').trim().toLowerCase();
    const rawPassword = String(password ?? '');

    if (!lookup || !rawPassword) {
      res.status(400).json({ error: 'Email/username and password are required.' });
      return;
    }

    const userRow = await findUserByIdentifier(lookup);

    // Explicitly block standard password login from accessing any admin account
    if (!userRow || !userRow.passwordHash || userRow.role === 'admin' || isAdminEmail(userRow.email)) {
      await logAuditEvent({
        actorId: userRow?.id ?? null,
        actorUsername: lookup,
        action: 'LOGIN_FAILED',
        status: 'denied',
        detail:
          userRow?.role === 'admin'
            ? 'Blocked standard login attempt targeting administrator account.'
            : 'Login rejected: invalid credentials.',
      });
      res.status(401).json({ error: 'Invalid credentials.' });
      return;
    }

    const valid = await bcrypt.compare(rawPassword, userRow.passwordHash);
    if (!valid) {
      await logAuditEvent({
        actorId: userRow.id,
        actorUsername: userRow.username,
        action: 'LOGIN_FAILED',
        status: 'denied',
        detail: 'Login rejected: bcrypt password verification failed.',
      });
      res.status(401).json({ error: 'Invalid credentials.' });
      return;
    }

    if (!userRow.emailVerified) {
      await logAuditEvent({
        actorId: userRow.id,
        actorUsername: userRow.username,
        action: 'LOGIN_UNVERIFIED',
        status: 'denied',
        detail: 'Blocked login attempt before email OTP verification was completed.',
      });
      res.status(403).json({
        error: 'Email verification required before signing in. Enter the 6-digit code sent to your email.',
        code: 'EMAIL_NOT_VERIFIED',
        email: userRow.email,
      });
      return;
    }

    const user = {
      id: userRow.id,
      username: userRow.username,
      email: userRow.email,
      role: userRow.role as UserRole,
    };
    const token = issueToken(user, 'password');

    await logAuditEvent({
      actorId: user.id,
      actorUsername: user.username,
      action: 'LOGIN',
      status: 'success',
      detail: `Authenticated via bcrypt after email verification; issued signed JWT (role: ${user.role}).`,
    });

    res.json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Authentication service failed.' });
  }
});

// -----------------------------------------------------------------------------
// Obscured Operator (Admin-Only) Authentication Routes
// -----------------------------------------------------------------------------

router.post('/auth/operator-google', async (req, res) => {
  try {
    const { idToken } = req.body ?? {};
    if (!idToken || typeof idToken !== 'string') {
      res.status(400).json({ error: 'Missing Firebase ID token.' });
      return;
    }

    const decoded = await adminAuth.verifyIdToken(idToken);
    const email = decoded.email?.trim().toLowerCase() ?? '';

    if (!email || !isAdminEmail(email)) {
      await logAuditEvent({
        actorId: null,
        actorUsername: email || decoded.uid,
        action: 'OPERATOR_ACCESS_DENIED',
        status: 'alert',
        detail: `Blocked unauthorized Google Sign-In attempt on operator gate (${email || 'unknown'}).`,
      });
      res.status(403).json({ error: 'Access denied: account is not authorized as system administrator.' });
      return;
    }

    const adminUser = await ensureAdminUserRecord({
      uid: decoded.uid,
      email,
      displayName: decoded.name,
    });

    await logAuditEvent({
      actorId: adminUser.id,
      actorUsername: adminUser.username,
      action: 'OPERATOR_LOGIN',
      status: 'success',
      detail: `Administrator authenticated via Google Sign-In (${adminUser.email}).`,
    });

    res.json({
      user: {
        id: adminUser.id,
        username: adminUser.username,
        email: adminUser.email,
        role: adminUser.role,
      },
    });
  } catch (error) {
    console.error('Operator Google auth error:', error);
    res.status(401).json({ error: 'Failed to verify administrator Google session.' });
  }
});

router.post('/auth/operator-passkey', async (req, res) => {
  try {
    const configuredPasskey = (process.env.ADMIN_PASSKEY ?? '').trim();
    if (!configuredPasskey) {
      res.status(403).json({
        error: 'Local operator passkey is not configured. Use Google Sign-In or set ADMIN_PASSKEY in .env.',
      });
      return;
    }

    const { email, passkey } = req.body ?? {};
    const cleanEmail = String(email ?? '').trim().toLowerCase();
    const providedPasskey = String(passkey ?? '');

    if (!isAdminEmail(cleanEmail)) {
      await logAuditEvent({
        actorId: null,
        actorUsername: cleanEmail || 'unknown',
        action: 'OPERATOR_ACCESS_DENIED',
        status: 'alert',
        detail: 'Blocked passkey login with non-admin email.',
      });
      res.status(403).json({ error: 'Invalid operator credentials.' });
      return;
    }

    const expectedBuf = Buffer.from(configuredPasskey, 'utf8');
    const providedBuf = Buffer.from(providedPasskey, 'utf8');
    const passkeyMatches =
      expectedBuf.length === providedBuf.length &&
      crypto.timingSafeEqual(expectedBuf, providedBuf);

    if (!passkeyMatches) {
      await logAuditEvent({
        actorId: null,
        actorUsername: cleanEmail,
        action: 'OPERATOR_ACCESS_DENIED',
        status: 'alert',
        detail: 'Blocked operator login: invalid ADMIN_PASSKEY.',
      });
      res.status(403).json({ error: 'Invalid operator credentials.' });
      return;
    }

    const adminUser = await ensureAdminUserRecord({
      email: getAdminEmail(),
    });
    const token = issueToken(adminUser, 'operator');

    await logAuditEvent({
      actorId: adminUser.id,
      actorUsername: adminUser.username,
      action: 'OPERATOR_LOGIN',
      status: 'success',
      detail: 'Administrator authenticated via local ADMIN_PASSKEY.',
    });

    res.json({
      token,
      user: {
        id: adminUser.id,
        username: adminUser.username,
        email: adminUser.email,
        role: adminUser.role,
      },
    });
  } catch (error) {
    console.error('Operator passkey error:', error);
    res.status(500).json({ error: 'Operator authentication failed.' });
  }
});

router.get('/auth/me', authenticateJWT, (req: AuthenticatedRequest, res) => {
  res.json({ user: req.user });
});

// -----------------------------------------------------------------------------
// User Directory & RBAC Role Management
// -----------------------------------------------------------------------------

router.get('/users', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    if (req.user!.role === 'admin') {
      const rows = await db
        .select({
          id: users.id,
          username: users.username,
          email: users.email,
          role: users.role,
          created_at: users.createdAt,
        })
        .from(users)
        .orderBy(asc(users.username));
      res.json({ users: rows });
      return;
    }

    // Standard users can only view verified non-admin peer usernames for ACL sharing
    const rows = await db
      .select({
        id: users.id,
        username: users.username,
        role: users.role,
      })
      .from(users)
      .where(and(ne(users.role, 'admin'), ne(users.id, req.user!.id), eq(users.emailVerified, true)))
      .orderBy(asc(users.username));

    res.json({
      users: rows.map((u) => ({
        id: u.id,
        username: u.username,
        email: '',
        role: u.role,
      })),
    });
  } catch (error) {
    console.error('Fetch users error:', error);
    res.status(500).json({ error: 'Failed to load user directory.' });
  }
});

router.patch('/users/:id/role', authenticateJWT, requireRole('admin'), async (req: AuthenticatedRequest, res) => {
  try {
    const { role } = req.body ?? {};
    if (role !== 'member' && role !== 'viewer') {
      res.status(400).json({ error: 'Users may only be assigned "member" or "viewer" roles.' });
      return;
    }

    const rows = await db
      .select({ id: users.id, username: users.username, email: users.email, role: users.role })
      .from(users)
      .where(eq(users.id, req.params.id))
      .limit(1);

    if (rows.length === 0) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const target = rows[0];
    if (target.id === req.user!.id || isAdminEmail(target.email)) {
      res.status(400).json({ error: 'Primary administrator role cannot be modified.' });
      return;
    }

    await db.update(users).set({ role }).where(eq(users.id, target.id));

    await logAuditEvent({
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      action: 'RBAC_ROLE_UPDATED',
      status: 'success',
      detail: `Changed ${target.username} RBAC role from "${target.role}" to "${role}".`,
    });

    res.json({ id: target.id, username: target.username, email: target.email, role });
  } catch (error) {
    console.error('Update user role error:', error);
    res.status(500).json({ error: 'Failed to update user role.' });
  }
});

// -----------------------------------------------------------------------------
// Encrypted File Vault & Access Control List Routes
// -----------------------------------------------------------------------------

router.get('/files', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;

    const ownedRows = await db
      .select({
        id: files.id,
        ownerId: files.ownerId,
        originalName: files.originalName,
        mimeType: files.mimeType,
        sizeBytes: files.sizeBytes,
        storageFilename: files.storageFilename,
        ivHex: files.ivHex,
        authTagHex: files.authTagHex,
        sha256Hash: files.sha256Hash,
        ciphertext: files.ciphertext,
        tamperBackup: files.tamperBackup,
        createdAt: files.createdAt,
        ownerUsername: users.username,
      })
      .from(files)
      .innerJoin(users, eq(users.id, files.ownerId))
      .where(eq(files.ownerId, userId))
      .orderBy(desc(files.createdAt));

    const sharedRows = await db
      .select({
        id: files.id,
        ownerId: files.ownerId,
        originalName: files.originalName,
        mimeType: files.mimeType,
        sizeBytes: files.sizeBytes,
        storageFilename: files.storageFilename,
        ivHex: files.ivHex,
        authTagHex: files.authTagHex,
        sha256Hash: files.sha256Hash,
        ciphertext: files.ciphertext,
        tamperBackup: files.tamperBackup,
        createdAt: files.createdAt,
        ownerUsername: users.username,
        sharedPermission: accessControlLists.permission,
      })
      .from(accessControlLists)
      .innerJoin(files, eq(files.id, accessControlLists.fileId))
      .innerJoin(users, eq(users.id, files.ownerId))
      .where(and(eq(accessControlLists.userId, userId), ne(files.ownerId, userId)))
      .orderBy(desc(files.createdAt));

    const ownedIds = ownedRows.map((r) => r.id);
    const aclByFile = new Map<
      string,
      Array<{
        id: string;
        user_id: string;
        permission: string;
        created_at: string;
        username: string;
        email: string;
        role: string;
      }>
    >();

    if (ownedIds.length > 0) {
      const aclRows = await db
        .select({
          id: accessControlLists.id,
          fileId: accessControlLists.fileId,
          userId: accessControlLists.userId,
          permission: accessControlLists.permission,
          createdAt: accessControlLists.createdAt,
          username: users.username,
          email: users.email,
          role: users.role,
        })
        .from(accessControlLists)
        .innerJoin(users, eq(users.id, accessControlLists.userId))
        .where(inArray(accessControlLists.fileId, ownedIds))
        .orderBy(asc(users.username));

      for (const entry of aclRows) {
        const list = aclByFile.get(entry.fileId) ?? [];
        list.push({
          id: entry.id,
          user_id: entry.userId,
          permission: entry.permission,
          created_at: entry.createdAt.toISOString(),
          username: entry.username,
          email: req.user!.role === 'admin' ? entry.email : '',
          role: entry.role,
        });
        aclByFile.set(entry.fileId, list);
      }
    }

    const ownedFiles = ownedRows.map((file) => {
      const currentSha256 = computeSha256(file.ciphertext);
      return {
        id: file.id,
        original_name: file.originalName,
        mime_type: file.mimeType,
        size_bytes: file.sizeBytes,
        storage_filename: file.storageFilename,
        iv_hex: file.ivHex,
        auth_tag_hex: file.authTagHex,
        sha256_hash: file.sha256Hash,
        created_at: file.createdAt.toISOString(),
        owner_id: file.ownerId,
        owner_username: file.ownerUsername,
        access_level: 'owner' as const,
        is_intact: currentSha256 === file.sha256Hash,
        is_tamper_backup_present: file.tamperBackup !== null,
        encrypted_bytes: file.ciphertext.length,
        acl: aclByFile.get(file.id) ?? [],
      };
    });

    const sharedFiles = sharedRows.map((file) => {
      const currentSha256 = computeSha256(file.ciphertext);
      return {
        id: file.id,
        original_name: file.originalName,
        mime_type: file.mimeType,
        size_bytes: file.sizeBytes,
        storage_filename: file.storageFilename,
        iv_hex: file.ivHex,
        auth_tag_hex: file.authTagHex,
        sha256_hash: file.sha256Hash,
        created_at: file.createdAt.toISOString(),
        owner_id: file.ownerId,
        owner_username: file.ownerUsername,
        access_level: file.sharedPermission as 'read' | 'write',
        is_intact: currentSha256 === file.sha256Hash,
        is_tamper_backup_present: file.tamperBackup !== null,
        encrypted_bytes: file.ciphertext.length,
        acl: [],
      };
    });

    res.json({ ownedFiles, sharedFiles });
  } catch (error) {
    console.error('List files error:', error);
    res.status(500).json({ error: 'Failed to retrieve encrypted vault files.' });
  }
});

router.post(
  '/files/upload',
  authenticateJWT,
  requireRole('admin', 'member'),
  upload.single('file'),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      if (!req.file) {
        res.status(400).json({ error: 'No file uploaded. Attach a file in the "file" field.' });
        return;
      }

      const fileId = crypto.randomUUID();
      const safeOriginalName = path.basename(req.file.originalname).replace(/[\r\n"]/g, '_') || 'unnamed.bin';
      const storageFilename = `${fileId}.enc`;
      const encrypted = encryptBuffer(req.file.buffer);

      const inserted = await db
        .insert(files)
        .values({
          id: fileId,
          ownerId: req.user!.id,
          originalName: safeOriginalName,
          mimeType: req.file.mimetype || 'application/octet-stream',
          sizeBytes: req.file.size,
          storageFilename,
          ivHex: encrypted.ivHex,
          authTagHex: encrypted.authTagHex,
          saltHex: encrypted.saltHex,
          sha256Hash: encrypted.sha256Hash,
          ciphertext: encrypted.ciphertext,
          tamperBackup: null,
        })
        .returning({ createdAt: files.createdAt });

      await logAuditEvent({
        actorId: req.user!.id,
        actorUsername: req.user!.username,
        action: 'UPLOAD',
        targetFileId: fileId,
        targetFilename: safeOriginalName,
        status: 'success',
        detail: `Encrypted ${req.file.size} bytes with AES-256-GCM; persisted in PostgreSQL (${storageFilename}).`,
      });

      res.status(201).json({
        file: {
          id: fileId,
          original_name: safeOriginalName,
          mime_type: req.file.mimetype || 'application/octet-stream',
          size_bytes: req.file.size,
          storage_filename: storageFilename,
          iv_hex: encrypted.ivHex,
          auth_tag_hex: encrypted.authTagHex,
          sha256_hash: encrypted.sha256Hash,
          created_at: inserted[0].createdAt.toISOString(),
        },
      });
    } catch (error) {
      console.error('Upload error:', error);
      res.status(500).json({ error: 'Failed to encrypt and save file.' });
    }
  },
);

router.get('/files/:id/download', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const fileRows = await db
      .select()
      .from(files)
      .where(eq(files.id, req.params.id))
      .limit(1);

    if (fileRows.length === 0) {
      res.status(404).json({ error: 'File record not found.' });
      return;
    }

    const file = fileRows[0];
    const isOwner = file.ownerId === req.user!.id;
    const aclRows = await db
      .select({ permission: accessControlLists.permission })
      .from(accessControlLists)
      .where(
        and(
          eq(accessControlLists.fileId, file.id),
          eq(accessControlLists.userId, req.user!.id),
        ),
      )
      .limit(1);

    const aclEntry = aclRows[0];

    if (!isOwner && !aclEntry) {
      await logAuditEvent({
        actorId: req.user!.id,
        actorUsername: req.user!.username,
        action: 'DOWNLOAD_DENIED',
        targetFileId: file.id,
        targetFilename: file.originalName,
        status: 'denied',
        detail: `Blocked unauthorized download attempt by ${req.user!.username} (not owner and no ACL entry).`,
      });
      res.status(403).json({
        error: 'Access Denied: You do not own this file and have not been granted ACL permission.',
        code: 'ACL_ACCESS_DENIED',
      });
      return;
    }

    try {
      const plaintext = verifyAndDecryptBuffer(
        file.ciphertext,
        file.ivHex,
        file.authTagHex,
        file.saltHex,
        file.sha256Hash,
      );

      await logAuditEvent({
        actorId: req.user!.id,
        actorUsername: req.user!.username,
        action: 'DOWNLOAD',
        targetFileId: file.id,
        targetFilename: file.originalName,
        status: 'success',
        detail: `Verified SHA-256 + AES-256-GCM tag and served decrypted file (${isOwner ? 'owner' : `ACL:${aclEntry?.permission}`}).`,
      });

      res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.send(plaintext);
    } catch (err) {
      if (err instanceof IntegrityError) {
        await logAuditEvent({
          actorId: req.user!.id,
          actorUsername: req.user!.username,
          action: 'INTEGRITY_FAILURE',
          targetFileId: file.id,
          targetFilename: file.originalName,
          status: 'alert',
          detail: `${err.message} Expected ${err.expectedHash?.slice(0, 12)}..., computed ${err.computedHash?.slice(0, 12)}...`,
        });
        res.status(422).json({
          error: err.message,
          code: 'INTEGRITY_VERIFICATION_FAILED',
          expectedSha256: err.expectedHash,
          computedSha256: err.computedHash,
        });
        return;
      }
      res.status(500).json({ error: 'Failed to decrypt vault artifact.' });
    }
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Failed to process file download.' });
  }
});

router.post('/files/:id/share', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const fileRows = await db
      .select()
      .from(files)
      .where(eq(files.id, req.params.id))
      .limit(1);

    if (fileRows.length === 0) {
      res.status(404).json({ error: 'File not found.' });
      return;
    }

    const file = fileRows[0];
    if (file.ownerId !== req.user!.id) {
      await logAuditEvent({
        actorId: req.user!.id,
        actorUsername: req.user!.username,
        action: 'SHARE_DENIED',
        targetFileId: file.id,
        targetFilename: file.originalName,
        status: 'denied',
        detail: 'Blocked non-owner attempt to modify file Access Control List.',
      });
      res.status(403).json({ error: 'Only the file owner may manage sharing permissions.' });
      return;
    }

    const { userId, permission } = req.body ?? {};
    const cleanPerm = permission === 'write' ? 'write' : 'read';

    const recipientRows = await db
      .select({ id: users.id, username: users.username, email: users.email, role: users.role })
      .from(users)
      .where(eq(users.id, String(userId ?? '')))
      .limit(1);

    if (recipientRows.length === 0) {
      res.status(404).json({ error: 'Recipient user does not exist.' });
      return;
    }

    const recipient = recipientRows[0];
    if (recipient.id === req.user!.id) {
      res.status(400).json({ error: 'You already own this file.' });
      return;
    }
    if (recipient.role === 'admin' && req.user!.role !== 'admin') {
      res.status(403).json({ error: 'Cannot target reserved system accounts.' });
      return;
    }

    await db
      .insert(accessControlLists)
      .values({
        id: crypto.randomUUID(),
        fileId: file.id,
        userId: recipient.id,
        permission: cleanPerm,
        grantedBy: req.user!.id,
      })
      .onConflictDoUpdate({
        target: [accessControlLists.fileId, accessControlLists.userId],
        set: {
          permission: cleanPerm,
          grantedBy: req.user!.id,
          createdAt: new Date(),
        },
      });

    await logAuditEvent({
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      action: 'SHARE_GRANTED',
      targetFileId: file.id,
      targetFilename: file.originalName,
      status: 'success',
      detail: `Granted "${cleanPerm}" ACL permission to ${recipient.username}.`,
    });

    res.status(201).json({
      entry: {
        user_id: recipient.id,
        username: recipient.username,
        email: req.user!.role === 'admin' ? recipient.email : '',
        role: recipient.role,
        permission: cleanPerm,
      },
    });
  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ error: 'Failed to update Access Control List.' });
  }
});

router.delete('/files/:id/share/:userId', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const fileRows = await db
      .select()
      .from(files)
      .where(eq(files.id, req.params.id))
      .limit(1);

    if (fileRows.length === 0) {
      res.status(404).json({ error: 'File not found.' });
      return;
    }

    const file = fileRows[0];
    if (file.ownerId !== req.user!.id) {
      res.status(403).json({ error: 'Only the file owner may revoke access.' });
      return;
    }

    const targetRows = await db
      .select({ username: users.username })
      .from(users)
      .where(eq(users.id, req.params.userId))
      .limit(1);

    await db
      .delete(accessControlLists)
      .where(
        and(
          eq(accessControlLists.fileId, file.id),
          eq(accessControlLists.userId, req.params.userId),
        ),
      );

    await logAuditEvent({
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      action: 'SHARE_REVOKED',
      targetFileId: file.id,
      targetFilename: file.originalName,
      status: 'success',
      detail: `Revoked ACL access for ${targetRows[0]?.username ?? req.params.userId}.`,
    });

    res.json({ ok: true });
  } catch (error) {
    console.error('Revoke share error:', error);
    res.status(500).json({ error: 'Failed to revoke ACL access.' });
  }
});

router.delete('/files/:id', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const fileRows = await db
      .select()
      .from(files)
      .where(eq(files.id, req.params.id))
      .limit(1);

    if (fileRows.length === 0) {
      res.status(404).json({ error: 'File not found.' });
      return;
    }

    const file = fileRows[0];
    if (file.ownerId !== req.user!.id && req.user!.role !== 'admin') {
      res.status(403).json({ error: 'Only the file owner or an Admin may delete this file.' });
      return;
    }

    await db.delete(files).where(eq(files.id, file.id));

    await logAuditEvent({
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      action: 'FILE_DELETED',
      targetFileId: file.id,
      targetFilename: file.originalName,
      status: 'success',
      detail: `Deleted encrypted ciphertext record ${file.storageFilename} and associated ACLs.`,
    });

    res.json({ ok: true });
  } catch (error) {
    console.error('Delete file error:', error);
    res.status(500).json({ error: 'Failed to delete file.' });
  }
});

// -----------------------------------------------------------------------------
// Security Inspector & Ciphertext Tamper Simulator Routes
// -----------------------------------------------------------------------------

router.get('/inspector/files', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const userAclRows = await db
      .select({ fileId: accessControlLists.fileId })
      .from(accessControlLists)
      .where(eq(accessControlLists.userId, req.user!.id));

    const sharedSet = new Set(userAclRows.map((a) => a.fileId));
    const sharedIds = Array.from(sharedSet);

    const isAdmin = req.user!.role === 'admin';

    const rows = await db
      .select({
        id: files.id,
        originalName: files.originalName,
        ownerId: files.ownerId,
        ownerUsername: users.username,
        sizeBytes: files.sizeBytes,
        storageFilename: files.storageFilename,
        ivHex: files.ivHex,
        authTagHex: files.authTagHex,
        saltHex: files.saltHex,
        sha256Hash: files.sha256Hash,
        ciphertext: files.ciphertext,
        tamperBackup: files.tamperBackup,
        createdAt: files.createdAt,
      })
      .from(files)
      .innerJoin(users, eq(users.id, files.ownerId))
      .where(
        isAdmin
          ? undefined
          : sharedIds.length > 0
            ? or(eq(files.ownerId, req.user!.id), inArray(files.id, sharedIds))
            : eq(files.ownerId, req.user!.id),
      )
      .orderBy(desc(files.createdAt));

    const artifacts = rows.map((file) => {
      const currentSha256 = computeSha256(file.ciphertext);
      return {
        id: file.id,
        original_name: file.originalName,
        owner_id: file.ownerId,
        owner_username: file.ownerUsername,
        is_authorized_for_download: file.ownerId === req.user!.id || sharedSet.has(file.id),
        size_bytes: file.sizeBytes,
        encrypted_bytes: file.ciphertext.length,
        storage_filename: file.storageFilename,
        iv_hex: file.ivHex,
        auth_tag_hex: file.authTagHex,
        salt_hex: file.saltHex,
        sha256_hash: file.sha256Hash,
        current_sha256: currentSha256,
        is_intact: currentSha256 === file.sha256Hash,
        is_tamper_backup_present: file.tamperBackup !== null,
        created_at: file.createdAt.toISOString(),
      };
    });

    res.json({ artifacts });
  } catch (error) {
    console.error('Inspector list error:', error);
    res.status(500).json({ error: 'Failed to inspect encrypted vault records.' });
  }
});

router.get('/inspector/:id', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const rows = await db
      .select({
        id: files.id,
        originalName: files.originalName,
        ownerId: files.ownerId,
        ownerUsername: users.username,
        sizeBytes: files.sizeBytes,
        storageFilename: files.storageFilename,
        ivHex: files.ivHex,
        authTagHex: files.authTagHex,
        saltHex: files.saltHex,
        sha256Hash: files.sha256Hash,
        ciphertext: files.ciphertext,
        tamperBackup: files.tamperBackup,
      })
      .from(files)
      .innerJoin(users, eq(users.id, files.ownerId))
      .where(eq(files.id, req.params.id))
      .limit(1);

    if (rows.length === 0) {
      res.status(404).json({ error: 'Artifact not found.' });
      return;
    }

    const file = rows[0];
    const isOwner = file.ownerId === req.user!.id;
    const aclRows = await db
      .select({ permission: accessControlLists.permission })
      .from(accessControlLists)
      .where(
        and(
          eq(accessControlLists.fileId, file.id),
          eq(accessControlLists.userId, req.user!.id),
        ),
      )
      .limit(1);

    const isAuthorized = isOwner || aclRows.length > 0;
    if (!isAuthorized && req.user!.role !== 'admin') {
      res.status(403).json({ error: 'Access Denied: You are not authorized to inspect this artifact.' });
      return;
    }

    const currentSha256 = computeSha256(file.ciphertext);
    const slice = file.ciphertext.subarray(0, 384);

    const hexLines: Array<{ offset: string; hex: string; ascii: string }> = [];
    for (let i = 0; i < slice.length; i += 16) {
      const chunk = slice.subarray(i, i + 16);
      const offset = i.toString(16).padStart(8, '0');
      const hex = Array.from(chunk)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
      const ascii = Array.from(chunk)
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('');
      hexLines.push({ offset, hex, ascii });
    }

    res.json({
      artifact: {
        id: file.id,
        original_name: file.originalName,
        owner_id: file.ownerId,
        owner_username: file.ownerUsername,
        is_authorized_for_download: isAuthorized,
        can_simulate_tamper: isOwner || req.user!.role === 'admin',
        storage_path_display: `postgres://files/${file.storageFilename} (bytea)`,
        size_bytes: file.sizeBytes,
        encrypted_bytes: file.ciphertext.length,
        iv_hex: file.ivHex,
        auth_tag_hex: file.authTagHex,
        salt_hex: file.saltHex,
        stored_sha256: file.sha256Hash,
        current_sha256: currentSha256,
        is_intact: currentSha256 === file.sha256Hash,
        is_tamper_backup_present: file.tamperBackup !== null,
        hex_dump: hexLines,
        raw_base64_preview: slice.toString('base64'),
      },
    });
  } catch (error) {
    console.error('Inspector detail error:', error);
    res.status(500).json({ error: 'Failed to inspect encrypted artifact.' });
  }
});

router.post('/inspector/:id/tamper', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const fileRows = await db
      .select()
      .from(files)
      .where(eq(files.id, req.params.id))
      .limit(1);

    if (fileRows.length === 0) {
      res.status(404).json({ error: 'Artifact not found.' });
      return;
    }

    const file = fileRows[0];
    if (file.ownerId !== req.user!.id && req.user!.role !== 'admin') {
      res.status(403).json({ error: 'Only the file owner or an Admin may simulate storage tampering.' });
      return;
    }

    if (file.ciphertext.length === 0) {
      res.status(400).json({ error: 'Cannot tamper an empty ciphertext payload.' });
      return;
    }

    const backupBuffer = file.tamperBackup ?? Buffer.from(file.ciphertext);
    const mutatedBuffer = Buffer.from(file.ciphertext);
    mutatedBuffer[0] ^= 0xff;

    await db
      .update(files)
      .set({
        ciphertext: mutatedBuffer,
        tamperBackup: backupBuffer,
      })
      .where(eq(files.id, file.id));

    const newSha256 = computeSha256(mutatedBuffer);
    await logAuditEvent({
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      action: 'TAMPER_SIMULATED',
      targetFileId: file.id,
      targetFilename: file.originalName,
      status: 'alert',
      detail: `Simulated 1-byte ciphertext corruption at offset 0x00000000 (${file.storageFilename}).`,
    });

    res.json({
      ok: true,
      stored_sha256: file.sha256Hash,
      current_sha256: newSha256,
      is_intact: newSha256 === file.sha256Hash,
    });
  } catch (error) {
    console.error('Tamper simulation error:', error);
    res.status(500).json({ error: 'Failed to simulate ciphertext tampering.' });
  }
});

router.post('/inspector/:id/restore', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const fileRows = await db
      .select()
      .from(files)
      .where(eq(files.id, req.params.id))
      .limit(1);

    if (fileRows.length === 0) {
      res.status(404).json({ error: 'Artifact not found.' });
      return;
    }

    const file = fileRows[0];
    if (file.ownerId !== req.user!.id && req.user!.role !== 'admin') {
      res.status(403).json({ error: 'Only the file owner or an Admin may restore the ciphertext snapshot.' });
      return;
    }

    if (!file.tamperBackup) {
      res.status(400).json({ error: 'No clean backup snapshot exists for this file.' });
      return;
    }

    const restoredBuffer = Buffer.from(file.tamperBackup);
    await db
      .update(files)
      .set({
        ciphertext: restoredBuffer,
        tamperBackup: null,
      })
      .where(eq(files.id, file.id));

    const restoredSha256 = computeSha256(restoredBuffer);
    await logAuditEvent({
      actorId: req.user!.id,
      actorUsername: req.user!.username,
      action: 'TAMPER_RESTORED',
      targetFileId: file.id,
      targetFilename: file.originalName,
      status: 'success',
      detail: `Restored original encrypted payload ${file.storageFilename}; SHA-256 verified.`,
    });

    res.json({
      ok: true,
      current_sha256: restoredSha256,
      is_intact: restoredSha256 === file.sha256Hash,
    });
  } catch (error) {
    console.error('Restore error:', error);
    res.status(500).json({ error: 'Failed to restore original ciphertext.' });
  }
});

// -----------------------------------------------------------------------------
// Audit Log Route
// -----------------------------------------------------------------------------

router.get('/audit', authenticateJWT, async (req: AuthenticatedRequest, res) => {
  try {
    const statusFilter = req.query.status as string | undefined;
    const isAdmin = req.user!.role === 'admin';

    const conditions = [];

    if (!isAdmin) {
      const ownedFiles = await db
        .select({ id: files.id })
        .from(files)
        .where(eq(files.ownerId, req.user!.id));
      const ownedIds = ownedFiles.map((f) => f.id);

      if (ownedIds.length > 0) {
        conditions.push(
          or(eq(auditLogs.actorId, req.user!.id), inArray(auditLogs.targetFileId, ownedIds)),
        );
      } else {
        conditions.push(eq(auditLogs.actorId, req.user!.id));
      }
    }

    if (statusFilter === 'success' || statusFilter === 'denied' || statusFilter === 'alert') {
      conditions.push(eq(auditLogs.status, statusFilter));
    }

    const rows = await db
      .select()
      .from(auditLogs)
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(auditLogs.createdAt))
      .limit(100);

    res.json({
      logs: rows.map((row) => ({
        id: row.id,
        actor_id: row.actorId,
        actor_username: row.actorUsername,
        action: row.action,
        target_file_id: row.targetFileId,
        target_filename: row.targetFilename,
        status: row.status,
        detail: row.detail,
        created_at: row.createdAt.toISOString(),
      })),
      scope: isAdmin ? 'system' : 'personal',
    });
  } catch (error) {
    console.error('Audit logs error:', error);
    res.status(500).json({ error: 'Failed to load security audit logs.' });
  }
});

export default router;
