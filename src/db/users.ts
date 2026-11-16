import crypto from 'crypto';
import { eq, or } from 'drizzle-orm';
import { db } from './index.ts';
import { auditLogs, users } from './schema.ts';

export type UserRole = 'admin' | 'member' | 'viewer';

export function getAdminEmail(): string {
  return (process.env.ADMIN_EMAIL || 'osmanp999@gmail.com').trim().toLowerCase();
}

export function isAdminEmail(email: string): boolean {
  return email.trim().toLowerCase() === getAdminEmail();
}

export interface SafeUser {
  id: string;
  uid: string | null;
  username: string;
  email: string;
  role: UserRole;
  createdAt: Date;
}

export async function logAuditEvent(params: {
  actorId: string | null;
  actorUsername: string;
  action: string;
  targetFileId?: string | null;
  targetFilename?: string | null;
  status: 'success' | 'denied' | 'alert';
  detail: string;
}): Promise<void> {
  try {
    await db.insert(auditLogs).values({
      id: crypto.randomUUID(),
      actorId: params.actorId,
      actorUsername: params.actorUsername,
      action: params.action,
      targetFileId: params.targetFileId ?? null,
      targetFilename: params.targetFilename ?? null,
      status: params.status,
      detail: params.detail,
    });
  } catch (error) {
    console.error('Failed to persist audit event:', error);
  }
}

export async function ensureAdminUserRecord(params: {
  uid?: string | null;
  email: string;
  displayName?: string;
}): Promise<SafeUser> {
  try {
    const cleanEmail = params.email.trim().toLowerCase();
    if (!isAdminEmail(cleanEmail)) {
      throw new Error('Unauthorized admin identity.');
    }

    if (params.uid) {
      const byUid = await db
        .select()
        .from(users)
        .where(eq(users.uid, params.uid))
        .limit(1);

      if (byUid.length > 0) {
        const existing = byUid[0];
        if (existing.role !== 'admin' || existing.email !== cleanEmail || !existing.emailVerified) {
          const updated = await db
            .update(users)
            .set({ role: 'admin', email: cleanEmail, emailVerified: true })
            .where(eq(users.id, existing.id))
            .returning();
          return {
            id: updated[0].id,
            uid: updated[0].uid,
            username: updated[0].username,
            email: updated[0].email,
            role: 'admin',
            createdAt: updated[0].createdAt,
          };
        }
        return {
          id: existing.id,
          uid: existing.uid,
          username: existing.username,
          email: existing.email,
          role: 'admin',
          createdAt: existing.createdAt,
        };
      }
    }

    const byEmail = await db
      .select()
      .from(users)
      .where(eq(users.email, cleanEmail))
      .limit(1);

    if (byEmail.length > 0) {
      const existing = byEmail[0];
      const updated = await db
        .update(users)
        .set({
          role: 'admin',
          emailVerified: true,
          ...(params.uid ? { uid: params.uid } : {}),
        })
        .where(eq(users.id, existing.id))
        .returning();
      return {
        id: updated[0].id,
        uid: updated[0].uid,
        username: updated[0].username,
        email: updated[0].email,
        role: 'admin',
        createdAt: updated[0].createdAt,
      };
    }

    const baseUsername = (params.displayName || cleanEmail.split('@')[0] || 'operator')
      .toLowerCase()
      .replace(/[^a-z0-9_.-]/g, '')
      .slice(0, 20) || 'operator';

    let candidateUsername = baseUsername;
    const collision = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.username, candidateUsername))
      .limit(1);
    if (collision.length > 0) {
      candidateUsername = `${baseUsername}_admin`;
    }

    const id = params.uid || crypto.randomUUID();
    const inserted = await db
      .insert(users)
      .values({
        id,
        uid: params.uid ?? null,
        username: candidateUsername,
        email: cleanEmail,
        passwordHash: null,
        role: 'admin',
        emailVerified: true,
      })
      .onConflictDoUpdate({
        target: users.email,
        set: {
          role: 'admin',
          emailVerified: true,
          ...(params.uid ? { uid: params.uid } : {}),
        },
      })
      .returning();

    const created = inserted[0];
    return {
      id: created.id,
      uid: created.uid,
      username: created.username,
      email: created.email,
      role: 'admin',
      createdAt: created.createdAt,
    };
  } catch (error) {
    console.error('Admin user sync failed:', error);
    throw new Error('Failed to verify administrator account.', { cause: error });
  }
}

export async function findUserByIdentifier(identifier: string) {
  try {
    const clean = identifier.trim().toLowerCase();
    const rows = await db
      .select()
      .from(users)
      .where(or(eq(users.email, clean), eq(users.username, clean)))
      .limit(1);
    return rows[0] ?? null;
  } catch (error) {
    console.error('Database user lookup failed:', error);
    throw new Error('Failed to verify user credentials.', { cause: error });
  }
}
