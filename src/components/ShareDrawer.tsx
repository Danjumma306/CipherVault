import { useEffect, useState } from 'react';
import { Trash2, UserPlus, X } from 'lucide-react';
import { api, ApiError } from '../api';
import type { User, VaultFile } from '../types';

interface ShareDrawerProps {
  file: VaultFile | null;
  token: string;
  currentUserId: string;
  onClose: () => void;
  onUpdated: () => void;
}

export function ShareDrawer({
  file,
  token,
  currentUserId,
  onClose,
  onUpdated,
}: ShareDrawerProps) {
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [permission, setPermission] = useState<'read' | 'write'>('read');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!file) return;
    setError(null);
    api
      .getUsers(token)
      .then((res) => {
        const candidates = res.users.filter((u) => u.id !== currentUserId);
        setUsers(candidates);
        if (candidates.length > 0 && !selectedUserId) {
          setSelectedUserId(candidates[0].id);
        }
      })
      .catch((err) => {
        setError(err instanceof ApiError ? err.message : 'Failed to load user directory.');
      });
  }, [file, token, currentUserId]);

  if (!file) return null;

  async function handleGrant(e: React.FormEvent) {
    e.preventDefault();
    if (!file || !selectedUserId) return;
    setBusy(true);
    setError(null);
    try {
      await api.shareFile(token, file.id, selectedUserId, permission);
      onUpdated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to grant access.');
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke(userId: string) {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      await api.revokeShare(token, file.id, userId);
      onUpdated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to revoke access.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/60 backdrop-blur-[2px]">
      <div className="w-full max-w-md bg-[#111A2E] border-l border-[#24324F] h-full flex flex-col">
        <div className="px-6 py-5 border-b border-[#24324F] flex items-center justify-between gap-4">
          <div className="min-w-0">
            <h2 className="font-display text-base font-semibold text-[#F1F5F9] truncate">
              Access Control List
            </h2>
            <p className="mt-0.5 text-xs text-[#94A3B8] truncate">{file.original_name}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close Access Control List drawer"
            className="p-2 rounded-lg text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#17223B] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 flex-1 overflow-y-auto space-y-6">
          {error && (
            <div className="px-3.5 py-2.5 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/40 text-xs text-[#FCA5A5]">
              {error}
            </div>
          )}

          <form onSubmit={handleGrant} className="space-y-4">
            <div className="text-xs font-medium text-[#CBD5E1]">Grant File Permission</div>
            <div className="grid grid-cols-1 gap-3">
              <div>
                <label htmlFor="acl-user" className="block text-xs text-[#94A3B8] mb-1">
                  Recipient Account
                </label>
                <select
                  id="acl-user"
                  value={selectedUserId}
                  onChange={(e) => setSelectedUserId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#24324F] text-sm text-[#F1F5F9] focus:outline-none focus:border-[#3B82F6]"
                >
                  {users.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.email ? `${u.username} (${u.email}) — ${u.role}` : `${u.username} — ${u.role}`}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="acl-perm" className="block text-xs text-[#94A3B8] mb-1">
                  Permission Level
                </label>
                <select
                  id="acl-perm"
                  value={permission}
                  onChange={(e) => setPermission(e.target.value as 'read' | 'write')}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#24324F] text-sm text-[#F1F5F9] focus:outline-none focus:border-[#3B82F6]"
                >
                  <option value="read">read (Verify &amp; Download)</option>
                  <option value="write">write (Read + Collaborator)</option>
                </select>
              </div>
            </div>

            <button
              type="submit"
              disabled={busy || !selectedUserId}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-xs font-medium text-white transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              <UserPlus className="w-4 h-4" />
              {busy ? 'Updating ACL...' : 'Grant Access'}
            </button>
          </form>

          <div className="pt-6 border-t border-[#24324F]">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-medium text-[#CBD5E1]">Authorized Recipients</span>
              <span className="text-xs font-mono tabular-nums text-[#94A3B8]">
                {file.acl.length} {file.acl.length === 1 ? 'grant' : 'grants'}
              </span>
            </div>

            {file.acl.length === 0 ? (
              <div className="py-6 text-center border border-[#24324F] rounded-lg bg-[#0B1120]">
                <p className="text-xs text-[#94A3B8]">
                  Private file. Only you ({file.owner_username}) can decrypt and download it.
                </p>
              </div>
            ) : (
              <div className="divide-y divide-[#24324F] border border-[#24324F] rounded-lg bg-[#0B1120]">
                {file.acl.map((entry) => (
                  <div
                    key={entry.user_id}
                    className="px-4 py-3 flex items-center justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="text-sm font-medium text-[#F1F5F9] truncate">
                        {entry.username}
                      </div>
                      <div className="text-xs text-[#94A3B8] truncate">
                        {entry.email || entry.role} <span aria-hidden="true">·</span>{' '}
                        <span className="font-mono text-[#3B82F6]">{entry.permission}</span>
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => handleRevoke(entry.user_id)}
                      aria-label={`Revoke access for ${entry.username}`}
                      className="p-2 rounded-lg text-[#94A3B8] hover:text-[#EF4444] hover:bg-[#17223B] transition-colors shrink-0"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
