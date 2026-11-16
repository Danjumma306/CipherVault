import { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, Search, ShieldAlert, XCircle } from 'lucide-react';
import { api, ApiError } from '../api';
import type { AuditLogEntry, User, UserRole } from '../types';

interface AuditLogViewProps {
  token: string;
  currentUser: User;
  onUserUpdated: () => void;
}

export function AuditLogView({ token, currentUser, onUserUpdated }: AuditLogViewProps) {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [scope, setScope] = useState<'system' | 'personal'>('personal');
  const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'denied' | 'alert'>('all');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  const [users, setUsers] = useState<User[]>([]);
  const [roleFeedback, setRoleFeedback] = useState<string | null>(null);

  async function loadData() {
    setLoading(true);
    try {
      const [auditRes, usersRes] = await Promise.all([
        api.getAuditLogs(token, statusFilter),
        currentUser.role === 'admin' ? api.getUsers(token) : Promise.resolve({ users: [] }),
      ]);
      setLogs(auditRes.logs);
      setScope(auditRes.scope);
      setUsers(usersRes.users);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadData();
  }, [token, statusFilter, currentUser.role]);

  const filteredLogs = useMemo(() => {
    if (!search.trim()) return logs;
    const q = search.toLowerCase();
    return logs.filter(
      (l) =>
        l.actor_username.toLowerCase().includes(q) ||
        l.action.toLowerCase().includes(q) ||
        (l.target_filename ?? '').toLowerCase().includes(q) ||
        l.detail.toLowerCase().includes(q),
    );
  }, [logs, search]);

  async function handleRoleChange(userId: string, role: UserRole) {
    setRoleFeedback(null);
    try {
      const updated = await api.updateUserRole(token, userId, role);
      setRoleFeedback(`Updated ${updated.username} RBAC role to ${updated.role}.`);
      await loadData();
      onUserUpdated();
    } catch (err) {
      setRoleFeedback(err instanceof ApiError ? err.message : 'Unable to update role.');
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold text-[#F1F5F9]">
          Security Audit Ledger
        </h1>
        <p className="mt-1 text-sm text-[#94A3B8]">
          {scope === 'system'
            ? 'System-wide cryptographic, authentication, and authorization events visible to Admin.'
            : 'Events involving your account and owned vault files.'}
        </p>
      </div>

      {/* Admin RBAC Role Management Panel */}
      {currentUser.role === 'admin' && users.length > 0 && (
        <div className="bg-[#111A2E] border border-[#24324F] rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#24324F] flex items-center justify-between gap-4">
            <div>
              <h2 className="font-display text-sm font-semibold text-[#F1F5F9]">
                RBAC Role Directory
              </h2>
              <p className="text-xs text-[#94A3B8]">
                Admin controls role capabilities: members upload &amp; share; viewers are read-only on ACL grants.
              </p>
            </div>
            {roleFeedback && <span className="text-xs text-[#3B82F6]">{roleFeedback}</span>}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#24324F] text-xs font-medium text-[#94A3B8]">
                  <th className="py-2.5 px-5">Account</th>
                  <th className="py-2.5 px-4">Email</th>
                  <th className="py-2.5 px-5 text-right">Assigned RBAC Role</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#24324F] text-sm">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-[#17223B]/40">
                    <td className="py-2.5 px-5 font-medium text-[#F1F5F9]">{u.username}</td>
                    <td className="py-2.5 px-4 text-xs text-[#94A3B8]">{u.email}</td>
                    <td className="py-2.5 px-5 text-right">
                      <select
                        aria-label={`RBAC role for ${u.username}`}
                        value={u.role}
                        disabled={u.id === currentUser.id || u.role === 'admin'}
                        onChange={(e) => handleRoleChange(u.id, e.target.value as UserRole)}
                        className="px-2.5 py-1 rounded-md bg-[#0B1120] border border-[#24324F] text-xs font-mono text-[#F1F5F9] disabled:opacity-50 focus:outline-none focus:border-[#3B82F6]"
                      >
                        {u.role === 'admin' && <option value="admin">admin</option>}
                        <option value="member">member</option>
                        <option value="viewer">viewer</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Search & Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 text-[#64748B] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search actor, action, or filename..."
            className="w-full pl-9 pr-3.5 py-2 rounded-lg bg-[#111A2E] border border-[#24324F] text-sm text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#3B82F6]"
          />
        </div>

        <div className="flex items-center gap-1 p-1 bg-[#111A2E] border border-[#24324F] rounded-lg w-fit">
          {(['all', 'success', 'denied', 'alert'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setStatusFilter(tab)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                statusFilter === tab
                  ? 'bg-[#17223B] text-[#F1F5F9]'
                  : 'text-[#94A3B8] hover:text-[#F1F5F9]'
              }`}
            >
              {tab === 'all'
                ? 'All Events'
                : tab === 'success'
                  ? 'Success'
                  : tab === 'denied'
                    ? 'Denied'
                    : 'Integrity Alerts'}
            </button>
          ))}
        </div>
      </div>

      {/* Audit Table */}
      <div className="bg-[#111A2E] border border-[#24324F] rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-6 space-y-3 animate-pulse">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-6 bg-[#17223B] rounded" />
            ))}
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-[#94A3B8]">
            No security events match this filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#24324F] text-xs font-medium text-[#94A3B8]">
                  <th className="py-3 px-5">Outcome</th>
                  <th className="py-3 px-4">Event</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Detail</th>
                  <th className="py-3 px-5 text-right">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#24324F] text-sm">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#17223B]/50">
                    <td className="py-3 px-5 whitespace-nowrap">
                      {log.status === 'success' ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#10B981]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Verified
                        </span>
                      ) : log.status === 'denied' ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#F59E0B]">
                          <XCircle className="w-3.5 h-3.5" />
                          Denied
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#EF4444]">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          Alert
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-[#F1F5F9] whitespace-nowrap">
                      {log.action}
                    </td>
                    <td className="py-3 px-4 text-xs text-[#CBD5E1] whitespace-nowrap">
                      {log.actor_username}
                    </td>
                    <td className="py-3 px-4 text-xs text-[#94A3B8]">
                      {log.target_filename && (
                        <span className="text-[#F1F5F9] font-medium mr-1.5">
                          [{log.target_filename}]
                        </span>
                      )}
                      {log.detail}
                    </td>
                    <td className="py-3 px-5 text-right text-xs font-mono tabular-nums text-[#94A3B8] whitespace-nowrap">
                      {new Date(log.created_at).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })}
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
