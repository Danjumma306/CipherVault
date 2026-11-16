export type UserRole = 'admin' | 'member' | 'viewer';

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  created_at?: string;
}

export interface AclEntry {
  id?: string;
  user_id: string;
  username: string;
  email: string;
  role: UserRole;
  permission: 'read' | 'write';
  created_at?: string;
}

export interface VaultFile {
  id: string;
  original_name: string;
  mime_type: string;
  size_bytes: number;
  encrypted_bytes: number;
  storage_filename: string;
  iv_hex: string;
  auth_tag_hex: string;
  sha256_hash: string;
  created_at: string;
  owner_id: string;
  owner_username: string;
  access_level: 'owner' | 'read' | 'write';
  is_intact: boolean;
  is_tamper_backup_present: boolean;
  acl: AclEntry[];
}

export interface InspectorListItem {
  id: string;
  original_name: string;
  owner_id: string;
  owner_username: string;
  is_authorized_for_download: boolean;
  size_bytes: number;
  encrypted_bytes: number;
  storage_filename: string;
  iv_hex: string;
  auth_tag_hex: string;
  salt_hex: string;
  sha256_hash: string;
  current_sha256: string | null;
  is_intact: boolean;
  is_tamper_backup_present: boolean;
  created_at: string;
}

export interface HexDumpLine {
  offset: string;
  hex: string;
  ascii: string;
}

export interface InspectorDetail {
  id: string;
  original_name: string;
  owner_id: string;
  owner_username: string;
  is_authorized_for_download: boolean;
  can_simulate_tamper: boolean;
  storage_path_display: string;
  size_bytes: number;
  encrypted_bytes: number;
  iv_hex: string;
  auth_tag_hex: string;
  salt_hex: string;
  stored_sha256: string;
  current_sha256: string;
  is_intact: boolean;
  is_tamper_backup_present: boolean;
  hex_dump: HexDumpLine[];
  raw_base64_preview: string;
}

export interface AuditLogEntry {
  id: string;
  actor_id: string | null;
  actor_username: string;
  action: string;
  target_file_id: string | null;
  target_filename: string | null;
  status: 'success' | 'denied' | 'alert';
  detail: string;
  created_at: string;
}

export type ActiveView = 'vault' | 'shared' | 'inspector' | 'audit';
