import { useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileLock2,
  Search,
  Share2,
  ShieldAlert,
  Trash2,
  Upload,
} from 'lucide-react';
import { api, ApiError } from '../api';
import type { User, VaultFile } from '../types';

interface VaultViewProps {
  mode: 'owned' | 'shared';
  user: User;
  token: string;
  files: VaultFile[];
  loading: boolean;
  onRefresh: () => void;
  onOpenShare: (file: VaultFile) => void;
  onOpenInspector: (fileId: string) => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function VaultView({
  mode,
  user,
  token,
  files,
  loading,
  onRefresh,
  onOpenShare,
  onOpenInspector,
}: VaultViewProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [search, setSearch] = useState('');
  const [integrityFilter, setIntegrityFilter] = useState<'all' | 'intact' | 'tampered'>('all');
  const [uploading, setUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{
    type: 'success' | 'error';
    title: string;
    detail: string;
    expectedHash?: string;
    computedHash?: string;
  } | null>(null);

  const canUpload = mode === 'owned' && user.role !== 'viewer';

  const filteredFiles = useMemo(() => {
    return files.filter((file) => {
      const matchesQuery =
        !search.trim() ||
        file.original_name.toLowerCase().includes(search.toLowerCase()) ||
        file.owner_username.toLowerCase().includes(search.toLowerCase()) ||
        file.sha256_hash.toLowerCase().includes(search.toLowerCase());
      const matchesIntegrity =
        integrityFilter === 'all' ||
        (integrityFilter === 'intact' && file.is_intact) ||
        (integrityFilter === 'tampered' && !file.is_intact);
      return matchesQuery && matchesIntegrity;
    });
  }, [files, search, integrityFilter]);

  async function processUpload(selectedFile: File) {
    setFeedback(null);
    setUploading(true);
    try {
      const res = await api.uploadFile(token, selectedFile);
      setFeedback({
        type: 'success',
        title: `Encrypted and vaulted "${res.file.original_name}"`,
        detail: `AES-256-GCM ciphertext written to ${res.file.storage_filename} with SHA-256 ${res.file.sha256_hash.slice(0, 16)}...`,
      });
      onRefresh();
    } catch (err) {
      setFeedback({
        type: 'error',
        title: 'Upload rejected',
        detail: err instanceof ApiError ? err.message : 'Unable to encrypt and save file.',
      });
    } finally {
      setUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  }

  async function handleDownload(file: VaultFile) {
    setFeedback(null);
    setDownloadingId(file.id);
    try {
      await api.downloadFile(token, file.id, file.original_name);
      setFeedback({
        type: 'success',
        title: `Verified & decrypted "${file.original_name}"`,
        detail: `JWT, ACL permission, SHA-256 digest (${file.sha256_hash.slice(0, 16)}...), and AES-256-GCM auth tag passed.`,
      });
    } catch (err) {
      if (err instanceof ApiError) {
        setFeedback({
          type: 'error',
          title:
            err.status === 422
              ? `Integrity Verification Blocked "${file.original_name}"`
              : `Download Rejected (${err.status})`,
          detail: err.message,
          expectedHash: err.expectedSha256,
          computedHash: err.computedSha256,
        });
      } else {
        setFeedback({
          type: 'error',
          title: 'Download failed',
          detail: 'Unexpected network error during download.',
        });
      }
    } finally {
      setDownloadingId(null);
    }
  }

  async function handleDelete(file: VaultFile) {
    setFeedback(null);
    try {
      await api.deleteFile(token, file.id);
      setConfirmDeleteId(null);
      setFeedback({
        type: 'success',
        title: `Deleted "${file.original_name}"`,
        detail: `Removed encrypted disk blob ${file.storage_filename} and associated ACL grants.`,
      });
      onRefresh();
    } catch (err) {
      setFeedback({
        type: 'error',
        title: 'Delete rejected',
        detail: err instanceof ApiError ? err.message : 'Unable to delete file.',
      });
    }
  }

  return (
    <div className="space-y-6">
      {/* Header & Primary Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-[#F1F5F9]">
            {mode === 'owned' ? 'Encrypted File Vault' : 'Shared With Me'}
          </h1>
          <p className="mt-1 text-sm text-[#94A3B8]">
            {mode === 'owned'
              ? 'Files uploaded here are encrypted in memory with AES-256-GCM before touching disk.'
              : 'Files explicitly shared with your account via per-file Access Control Lists.'}
          </p>
        </div>

        {mode === 'owned' && (
          <div className="shrink-0">
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={(e) => {
                const chosen = e.target.files?.[0];
                if (chosen) void processUpload(chosen);
              }}
            />
            {canUpload ? (
              <button
                type="button"
                disabled={uploading}
                onClick={() => fileInputRef.current?.click()}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-sm font-medium text-white transition-colors disabled:opacity-50 whitespace-nowrap"
              >
                <Upload className="w-4 h-4" />
                {uploading ? 'Encrypting & Storing...' : 'Upload & Encrypt File'}
              </button>
            ) : (
              <div className="text-xs text-[#F59E0B]">
                RBAC notice: Viewer role cannot upload files
              </div>
            )}
          </div>
        )}
      </div>

      {/* Dropzone for Owned Vault (Members & Admins) */}
      {canUpload && (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragging(false);
            const dropped = e.dataTransfer.files?.[0];
            if (dropped) void processUpload(dropped);
          }}
          className={`border border-dashed rounded-xl px-6 py-5 transition-colors flex flex-col sm:flex-row items-center justify-between gap-4 ${
            isDragging
              ? 'border-[#3B82F6] bg-[#3B82F6]/10'
              : 'border-[#24324F] bg-[#111A2E]'
          }`}
        >
          <div className="flex items-center gap-3.5">
            <FileLock2 className="w-5 h-5 text-[#3B82F6] shrink-0" />
            <div>
              <div className="text-sm font-medium text-[#F1F5F9]">
                Drop any file to encrypt at rest (up to 15 MB)
              </div>
              <div className="text-xs text-[#94A3B8]">
                Generates a unique 128-bit HKDF salt, 96-bit random IV, AES-256-GCM tag, and SHA-256 digest.
              </div>
            </div>
          </div>
          <button
            type="button"
            disabled={uploading}
            onClick={() => fileInputRef.current?.click()}
            className="px-3.5 py-2 rounded-lg bg-[#17223B] hover:bg-[#1E2D4D] border border-[#24324F] text-xs font-medium text-[#F1F5F9] transition-colors whitespace-nowrap shrink-0"
          >
            Select File
          </button>
        </div>
      )}

      {/* Cryptographic / Access Feedback Banner */}
      {feedback && (
        <div
          role={feedback.type === 'error' ? 'alert' : 'status'}
          className={`px-4 py-3.5 rounded-xl border text-sm ${
            feedback.type === 'success'
              ? 'bg-[#10B981]/10 border-[#10B981]/30 text-[#D1FAE5]'
              : 'bg-[#EF4444]/10 border-[#EF4444]/40 text-[#FECACA]'
          }`}
        >
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-2.5">
              {feedback.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-[#10B981] mt-0.5 shrink-0" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-[#EF4444] mt-0.5 shrink-0" />
              )}
              <div>
                <div className="font-medium">{feedback.title}</div>
                <div className="mt-0.5 text-xs opacity-90">{feedback.detail}</div>
                {feedback.expectedHash && feedback.computedHash && (
                  <div className="mt-2 font-mono text-xs space-y-0.5 tabular-nums">
                    <div>Expected SHA-256: {feedback.expectedHash}</div>
                    <div>Computed SHA-256: {feedback.computedHash}</div>
                  </div>
                )}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setFeedback(null)}
              className="text-xs underline opacity-80 hover:opacity-100 shrink-0"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Search & Integrity Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 text-[#64748B] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by filename, owner, or SHA-256..."
            className="w-full pl-9 pr-3.5 py-2 rounded-lg bg-[#111A2E] border border-[#24324F] text-sm text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#3B82F6]"
          />
        </div>

        <div className="flex items-center gap-1 p-1 bg-[#111A2E] border border-[#24324F] rounded-lg w-fit">
          {(['all', 'intact', 'tampered'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setIntegrityFilter(tab)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                integrityFilter === tab
                  ? 'bg-[#17223B] text-[#F1F5F9]'
                  : 'text-[#94A3B8] hover:text-[#F1F5F9]'
              }`}
            >
              {tab === 'all' ? 'All Files' : tab === 'intact' ? 'Verified' : 'Tampered'}
            </button>
          ))}
        </div>
      </div>

      {/* File Table */}
      <div className="bg-[#111A2E] border border-[#24324F] rounded-xl overflow-hidden">
        {loading ? (
          <div className="divide-y divide-[#24324F]">
            {[1, 2, 3].map((row) => (
              <div key={row} className="px-5 py-4 flex items-center justify-between gap-4 animate-pulse">
                <div className="h-4 w-48 bg-[#17223B] rounded" />
                <div className="h-4 w-24 bg-[#17223B] rounded" />
                <div className="h-4 w-32 bg-[#17223B] rounded" />
              </div>
            ))}
          </div>
        ) : filteredFiles.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <p className="text-sm font-medium text-[#F1F5F9]">
              {files.length === 0
                ? mode === 'owned'
                  ? 'Your encrypted vault is empty'
                  : 'No files have been shared with your account'
                : 'No matching files found'}
            </p>
            <p className="mt-1 text-xs text-[#94A3B8]">
              {files.length === 0
                ? mode === 'owned'
                  ? canUpload
                    ? 'Upload a document above to encrypt it with AES-256-GCM and inspect its ciphertext.'
                    : 'Your viewer account can access files shared with you in Shared With Me.'
                  : 'Ask a file owner to grant you read or write permission from their Access Control List.'
                : 'Adjust your search query or integrity filter.'}
            </p>
            {mode === 'owned' && canUpload && files.length === 0 && (
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-xs font-medium text-white transition-colors"
              >
                <Upload className="w-4 h-4" />
                Upload First File
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#24324F] text-xs font-medium text-[#94A3B8]">
                  <th className="py-3 px-5">File &amp; Digest</th>
                  <th className="py-3 px-4 text-right">Size</th>
                  <th className="py-3 px-4">Access</th>
                  <th className="py-3 px-4">Disk Integrity</th>
                  <th className="py-3 px-4 text-right">Uploaded</th>
                  <th className="py-3 px-5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#24324F] text-sm">
                {filteredFiles.map((file) => (
                  <tr
                    key={file.id}
                    className="hover:bg-[#17223B]/60 transition-colors"
                  >
                    <td className="py-3 px-5">
                      <div className="font-medium text-[#F1F5F9]">{file.original_name}</div>
                      <div className="mt-0.5 text-xs text-[#94A3B8] font-mono tabular-nums">
                        SHA-256 {file.sha256_hash.slice(0, 14)}... <span aria-hidden="true">·</span>{' '}
                        IV {file.iv_hex.slice(0, 8)}...
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right font-mono text-xs tabular-nums text-[#CBD5E1] whitespace-nowrap">
                      {formatBytes(file.size_bytes)}
                    </td>

                    <td className="py-3 px-4 text-xs text-[#94A3B8] whitespace-nowrap">
                      {mode === 'owned' ? (
                        file.acl.length > 0 ? (
                          <span>
                            Owner <span aria-hidden="true">·</span> Shared with{' '}
                            <span className="text-[#F1F5F9] font-mono tabular-nums">
                              {file.acl.length}
                            </span>
                          </span>
                        ) : (
                          <span>Private (Owner only)</span>
                        )
                      ) : (
                        <span>
                          From <span className="text-[#F1F5F9]">{file.owner_username}</span>{' '}
                          <span aria-hidden="true">·</span>{' '}
                          <span className="font-mono text-[#3B82F6]">{file.access_level}</span>
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      {file.is_intact ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#10B981]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Verified
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#EF4444]">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Tampered
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-right text-xs text-[#94A3B8] tabular-nums whitespace-nowrap">
                      {formatTimestamp(file.created_at)}
                    </td>

                    <td className="py-3 px-5 text-right whitespace-nowrap">
                      <div className="inline-flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          disabled={downloadingId === file.id}
                          onClick={() => handleDownload(file)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-[#17223B] hover:bg-[#1E2D4D] border border-[#24324F] text-xs font-medium text-[#F1F5F9] transition-colors disabled:opacity-50"
                        >
                          <Download className="w-3.5 h-3.5" />
                          {downloadingId === file.id ? 'Verifying...' : 'Download'}
                        </button>

                        <button
                          type="button"
                          onClick={() => onOpenInspector(file.id)}
                          className="px-2.5 py-1.5 rounded-md border border-[#24324F] hover:border-[#3B82F6] text-xs font-medium text-[#CBD5E1] hover:text-[#F1F5F9] transition-colors"
                        >
                          Inspect
                        </button>

                        {mode === 'owned' && (
                          <button
                            type="button"
                            onClick={() => onOpenShare(file)}
                            aria-label={`Share ${file.original_name}`}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-[#24324F] hover:border-[#3B82F6] text-xs font-medium text-[#CBD5E1] hover:text-[#F1F5F9] transition-colors"
                          >
                            <Share2 className="w-3.5 h-3.5" />
                            Share
                          </button>
                        )}

                        {(mode === 'owned' || user.role === 'admin') &&
                          (confirmDeleteId === file.id ? (
                            <div className="inline-flex items-center gap-1 ml-1">
                              <button
                                type="button"
                                onClick={() => handleDelete(file)}
                                className="px-2 py-1 rounded bg-[#EF4444] text-xs font-medium text-white"
                              >
                                Confirm
                              </button>
                              <button
                                type="button"
                                onClick={() => setConfirmDeleteId(null)}
                                className="px-2 py-1 rounded border border-[#24324F] text-xs text-[#94A3B8]"
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <button
                              type="button"
                              aria-label={`Delete ${file.original_name}`}
                              onClick={() => setConfirmDeleteId(file.id)}
                              className="p-1.5 rounded-md text-[#94A3B8] hover:text-[#EF4444] hover:bg-[#17223B] transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
