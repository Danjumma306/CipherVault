import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const VAULT_KEY_PATH = path.join(DATA_DIR, '.vault-dev.key');
const JWT_KEY_PATH = path.join(DATA_DIR, '.jwt-dev.key');

function ensureDataDir(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function loadOrCreateHexSecret(envVar: string | undefined, fallbackFilePath: string, byteLength: number): Buffer {
  if (envVar && /^[0-9a-fA-F]+$/.test(envVar) && envVar.length === byteLength * 2) {
    return Buffer.from(envVar, 'hex');
  }
  if (envVar && envVar.length >= byteLength) {
    return crypto.createHash('sha256').update(envVar).digest().subarray(0, byteLength);
  }
  ensureDataDir();
  if (fs.existsSync(fallbackFilePath)) {
    const raw = fs.readFileSync(fallbackFilePath, 'utf8').trim();
    if (/^[0-9a-fA-F]+$/.test(raw) && raw.length === byteLength * 2) {
      return Buffer.from(raw, 'hex');
    }
  }
  const generated = crypto.randomBytes(byteLength);
  fs.writeFileSync(fallbackFilePath, generated.toString('hex'), { mode: 0o600 });
  return generated;
}

const MASTER_KEY = loadOrCreateHexSecret(process.env.VAULT_MASTER_KEY, VAULT_KEY_PATH, 32);
export const JWT_SECRET = loadOrCreateHexSecret(process.env.JWT_SECRET, JWT_KEY_PATH, 32).toString('hex');

export interface EncryptedPayload {
  ciphertext: Buffer;
  ivHex: string;
  authTagHex: string;
  saltHex: string;
  sha256Hash: string;
}

export class IntegrityError extends Error {
  public readonly expectedHash?: string;
  public readonly computedHash?: string;

  constructor(message: string, expectedHash?: string, computedHash?: string) {
    super(message);
    this.name = 'IntegrityError';
    this.expectedHash = expectedHash;
    this.computedHash = computedHash;
  }
}

/**
 * Derives a unique 256-bit Data Encryption Key (DEK) per file using HKDF-SHA256
 * so compromising or rotating one file key context does not expose identical blocks.
 */
function deriveFileKey(saltHex: string): Buffer {
  const salt = Buffer.from(saltHex, 'hex');
  const derived = crypto.hkdfSync('sha256', MASTER_KEY, salt, Buffer.from('ciphervault-aes256gcm-dek-v1'), 32);
  return Buffer.from(derived);
}

/**
 * Encrypts a plaintext buffer in memory using AES-256-GCM with a random 96-bit IV
 * and 128-bit per-file HKDF salt, then computes a SHA-256 digest of the ciphertext.
 */
export function encryptBuffer(plaintext: Buffer): EncryptedPayload {
  const saltHex = crypto.randomBytes(16).toString('hex');
  const fileKey = deriveFileKey(saltHex);
  const iv = crypto.randomBytes(12); // NIST SP 800-38D recommended 96-bit IV for GCM

  const cipher = crypto.createCipheriv('aes-256-gcm', fileKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16-byte authentication tag

  const sha256Hash = crypto.createHash('sha256').update(ciphertext).digest('hex');

  return {
    ciphertext,
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    saltHex,
    sha256Hash,
  };
}

/**
 * Computes the SHA-256 hex digest of an encrypted disk buffer.
 */
export function computeSha256(buffer: Buffer): string {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Performs two-layer integrity verification (constant-time SHA-256 comparison
 * followed by AES-256-GCM authentication tag verification) before returning plaintext.
 */
export function verifyAndDecryptBuffer(
  ciphertext: Buffer,
  ivHex: string,
  authTagHex: string,
  saltHex: string,
  expectedSha256: string,
): Buffer {
  const computedHash = computeSha256(ciphertext);
  const expectedBuf = Buffer.from(expectedSha256, 'hex');
  const computedBuf = Buffer.from(computedHash, 'hex');

  if (expectedBuf.length !== computedBuf.length || !crypto.timingSafeEqual(expectedBuf, computedBuf)) {
    throw new IntegrityError(
      'SHA-256 integrity verification failed: encrypted blob on disk does not match stored digest.',
      expectedSha256,
      computedHash,
    );
  }

  try {
    const fileKey = deriveFileKey(saltHex);
    const decipher = crypto.createDecipheriv('aes-256-gcm', fileKey, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new IntegrityError(
      'AES-256-GCM authentication tag mismatch: ciphertext or metadata failed authenticated decryption.',
      expectedSha256,
      computedHash,
    );
  }
}
