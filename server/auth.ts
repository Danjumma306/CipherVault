import { eq } from 'drizzle-orm';
import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { db } from '../src/db/index.ts';
import { users } from '../src/db/schema.ts';
import { ensureAdminUserRecord, isAdminEmail, type UserRole } from '../src/db/users.ts';
import { adminAuth } from '../src/lib/firebase-admin.ts';
import { JWT_SECRET } from './crypto.ts';

export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  role: UserRole;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

interface JwtPayloadShape {
  sub: string;
  username: string;
  role: UserRole;
  authMethod?: 'password' | 'operator';
}

export function issueToken(
  user: Pick<AuthenticatedUser, 'id' | 'username' | 'role'>,
  authMethod: 'password' | 'operator' = 'password',
): string {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role,
      authMethod,
    },
    JWT_SECRET,
    { expiresIn: authMethod === 'operator' ? '2h' : '4h' },
  );
}

/**
 * Verifies either a standard password-issued JWT (non-admin only),
 * an operator-issued JWT, or a Firebase ID Token restricted to the designated admin email.
 */
export async function authenticateJWT(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required. Provide a valid Bearer token.' });
    return;
  }

  const token = authHeader.slice(7).trim();

  // 1. Try local HMAC-SHA256 JWT
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayloadShape;
    const rows = await db
      .select({
        id: users.id,
        username: users.username,
        email: users.email,
        role: users.role,
      })
      .from(users)
      .where(eq(users.id, decoded.sub))
      .limit(1);

    if (rows.length === 0) {
      res.status(401).json({ error: 'User account no longer exists.' });
      return;
    }

    const dbUser = rows[0];

    // Prevent standard password tokens from ever authenticating an admin account
    if (dbUser.role === 'admin' && decoded.authMethod !== 'operator') {
      res.status(403).json({ error: 'Administrator sessions must use the operator authentication channel.' });
      return;
    }

    req.user = {
      id: dbUser.id,
      username: dbUser.username,
      email: dbUser.email,
      role: dbUser.role as UserRole,
    };
    next();
    return;
  } catch {
    // Fall through to Firebase ID Token verification
  }

  // 2. Try Firebase Admin ID token verification (strictly restricted to designated Admin email)
  try {
    const decodedFirebase = await adminAuth.verifyIdToken(token);
    const email = decodedFirebase.email?.trim().toLowerCase() ?? '';
    if (!email || !isAdminEmail(email)) {
      res.status(403).json({ error: 'This Google account is not authorized for operator access.' });
      return;
    }

    const synced = await ensureAdminUserRecord({
      uid: decodedFirebase.uid,
      email,
      displayName: decodedFirebase.name,
    });

    req.user = {
      id: synced.id,
      username: synced.username,
      email: synced.email,
      role: 'admin',
    };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired authentication token.' });
  }
}

/**
 * Role-Based Access Control (RBAC) guard restricting endpoints to allowed roles.
 */
export function requireRole(...allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: `RBAC policy denies access: role "${req.user.role}" requires one of [${allowedRoles.join(', ')}].`,
      });
      return;
    }
    next();
  };
}
