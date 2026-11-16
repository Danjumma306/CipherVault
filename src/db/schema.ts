import { relations } from 'drizzle-orm';
import {
  boolean,
  customType,
  index,
  integer,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return 'bytea';
  },
});

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  uid: text('uid').unique(),
  username: text('username').notNull().unique(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash'),
  role: text('role').notNull().default('member'),
  emailVerified: boolean('email_verified').notNull().default(false),
  otpHash: text('otp_hash'),
  otpExpiresAt: timestamp('otp_expires_at', { withTimezone: true }),
  otpAttempts: integer('otp_attempts').notNull().default(0),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const files = pgTable(
  'files',
  {
    id: text('id').primaryKey(),
    ownerId: text('owner_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    originalName: text('original_name').notNull(),
    mimeType: text('mime_type').notNull(),
    sizeBytes: integer('size_bytes').notNull(),
    storageFilename: text('storage_filename').notNull().unique(),
    ivHex: text('iv_hex').notNull(),
    authTagHex: text('auth_tag_hex').notNull(),
    saltHex: text('salt_hex').notNull(),
    sha256Hash: text('sha256_hash').notNull(),
    ciphertext: bytea('ciphertext').notNull(),
    tamperBackup: bytea('tamper_backup'),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index('idx_files_owner').on(table.ownerId)],
);

export const accessControlLists = pgTable(
  'access_control_lists',
  {
    id: text('id').primaryKey(),
    fileId: text('file_id')
      .notNull()
      .references(() => files.id, { onDelete: 'cascade' }),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    permission: text('permission').notNull().default('read'),
    grantedBy: text('granted_by')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex('idx_acl_file_user').on(table.fileId, table.userId),
    index('idx_acl_user').on(table.userId),
    index('idx_acl_file').on(table.fileId),
  ],
);

export const auditLogs = pgTable(
  'audit_logs',
  {
    id: text('id').primaryKey(),
    actorId: text('actor_id').references(() => users.id, { onDelete: 'set null' }),
    actorUsername: text('actor_username').notNull(),
    action: text('action').notNull(),
    targetFileId: text('target_file_id'),
    targetFilename: text('target_filename'),
    status: text('status').notNull(),
    detail: text('detail').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index('idx_audit_created').on(table.createdAt)],
);

export const usersRelations = relations(users, ({ many }) => ({
  ownedFiles: many(files),
  aclEntries: many(accessControlLists),
}));

export const filesRelations = relations(files, ({ one, many }) => ({
  owner: one(users, {
    fields: [files.ownerId],
    references: [users.id],
  }),
  aclEntries: many(accessControlLists),
}));

export const accessControlListsRelations = relations(accessControlLists, ({ one }) => ({
  file: one(files, {
    fields: [accessControlLists.fileId],
    references: [files.id],
  }),
  user: one(users, {
    fields: [accessControlLists.userId],
    references: [users.id],
  }),
}));
