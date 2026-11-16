import type {
  AuditLogEntry,
  InspectorDetail,
  InspectorListItem,
  User,
  UserRole,
  VaultFile,
} from './types';

export interface RegisterOtpResponse {
  requiresVerification: boolean;
  email: string;
  expiresInMinutes: number;
  delivery: 'smtp' | 'ethereal' | 'dev-fallback';
  previewUrl?: string;
  devOtp?: string;
}

export class ApiError extends Error {
  public readonly status: number;
  public readonly code?: string;
  public readonly expectedSha256?: string;
  public readonly computedSha256?: string;
  public readonly email?: string;

  constructor(
    message: string,
    status: number,
    code?: string,
    expectedSha256?: string,
    computedSha256?: string,
    email?: string,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.expectedSha256 = expectedSha256;
    this.computedSha256 = computedSha256;
    this.email = email;
  }
}

async function apiFetch<T>(
  url: string,
  token: string | null,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(url, { ...options, headers });
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json() : null;

  if (!response.ok) {
    throw new ApiError(
      data?.error || `Request failed (${response.status})`,
      response.status,
      data?.code,
      data?.expectedSha256,
      data?.computedSha256,
      data?.email,
    );
  }

  return data as T;
}

export const api = {
  login(identifier: string, password: string): Promise<{ token: string; user: User }> {
    return apiFetch('/api/auth/login', null, {
      method: 'POST',
      body: JSON.stringify({ identifier, password }),
    });
  },

  register(username: string, email: string, password: string): Promise<RegisterOtpResponse> {
    return apiFetch('/api/auth/register', null, {
      method: 'POST',
      body: JSON.stringify({ username, email, password }),
    });
  },

  verifyOtp(
    email: string,
    otp: string,
  ): Promise<{ verified: boolean; email: string; message: string }> {
    return apiFetch('/api/auth/verify-otp', null, {
      method: 'POST',
      body: JSON.stringify({ email, otp }),
    });
  },

  resendOtp(email: string): Promise<RegisterOtpResponse> {
    return apiFetch('/api/auth/resend-otp', null, {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  verifyOperatorGoogle(idToken: string): Promise<{ user: User }> {
    return apiFetch('/api/auth/operator-google', null, {
      method: 'POST',
      body: JSON.stringify({ idToken }),
    });
  },

  loginOperatorPasskey(email: string, passkey: string): Promise<{ token: string; user: User }> {
    return apiFetch('/api/auth/operator-passkey', null, {
      method: 'POST',
      body: JSON.stringify({ email, passkey }),
    });
  },

  getMe(token: string): Promise<{ user: User }> {
    return apiFetch('/api/auth/me', token);
  },

  getUsers(token: string): Promise<{ users: User[] }> {
    return apiFetch('/api/users', token);
  },

  updateUserRole(token: string, userId: string, role: UserRole): Promise<User> {
    return apiFetch(`/api/users/${userId}/role`, token, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  },

  getFiles(token: string): Promise<{ ownedFiles: VaultFile[]; sharedFiles: VaultFile[] }> {
    return apiFetch('/api/files', token);
  },

  uploadFile(token: string, file: File): Promise<{ file: VaultFile }> {
    const formData = new FormData();
    formData.append('file', file);
    return apiFetch('/api/files/upload', token, {
      method: 'POST',
      body: formData,
    });
  },

  async downloadFile(token: string, fileId: string, fallbackName: string): Promise<void> {
    const response = await fetch(`/api/files/${fileId}/download`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      const data = await response.json().catch(() => null);
      throw new ApiError(
        data?.error || `Download rejected (${response.status})`,
        response.status,
        data?.code,
        data?.expectedSha256,
        data?.computedSha256,
      );
    }

    const blob = await response.blob();
    const disposition = response.headers.get('content-disposition');
    let filename = fallbackName;
    if (disposition) {
      const match = disposition.match(/filename="([^"]+)"/);
      if (match?.[1]) {
        filename = match[1];
      }
    }

    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = objectUrl;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
  },

  shareFile(
    token: string,
    fileId: string,
    userId: string,
    permission: 'read' | 'write',
  ): Promise<{ entry: unknown }> {
    return apiFetch(`/api/files/${fileId}/share`, token, {
      method: 'POST',
      body: JSON.stringify({ userId, permission }),
    });
  },

  revokeShare(token: string, fileId: string, userId: string): Promise<{ ok: boolean }> {
    return apiFetch(`/api/files/${fileId}/share/${userId}`, token, {
      method: 'DELETE',
    });
  },

  deleteFile(token: string, fileId: string): Promise<{ ok: boolean }> {
    return apiFetch(`/api/files/${fileId}`, token, {
      method: 'DELETE',
    });
  },

  getInspectorFiles(token: string): Promise<{ artifacts: InspectorListItem[] }> {
    return apiFetch('/api/inspector/files', token);
  },

  getInspectorDetail(token: string, fileId: string): Promise<{ artifact: InspectorDetail }> {
    return apiFetch(`/api/inspector/${fileId}`, token);
  },

  simulateTamper(
    token: string,
    fileId: string,
  ): Promise<{ ok: boolean; stored_sha256: string; current_sha256: string; is_intact: boolean }> {
    return apiFetch(`/api/inspector/${fileId}/tamper`, token, {
      method: 'POST',
    });
  },

  restoreTamper(
    token: string,
    fileId: string,
  ): Promise<{ ok: boolean; current_sha256: string; is_intact: boolean }> {
    return apiFetch(`/api/inspector/${fileId}/restore`, token, {
      method: 'POST',
    });
  },

  getAuditLogs(
    token: string,
    status?: 'all' | 'success' | 'denied' | 'alert',
  ): Promise<{ logs: AuditLogEntry[]; scope: 'system' | 'personal' }> {
    const query = status && status !== 'all' ? `?status=${status}` : '';
    return apiFetch(`/api/audit${query}`, token);
  },
};
