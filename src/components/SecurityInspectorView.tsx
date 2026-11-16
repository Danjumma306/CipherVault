import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  HardDrive,
  RotateCcw,
  ShieldAlert,
  Zap,
} from 'lucide-react';
import { api, ApiError } from '../api';
import type { InspectorDetail, InspectorListItem } from '../types';

interface SecurityInspectorViewProps {
  token: string;
  initialFileId: string | null;
  onDiskChanged: () => void;
}

export function SecurityInspectorView({
  token,
  initialFileId,
  onDiskChanged,
}: SecurityInspectorViewProps) {
  const [artifacts, setArtifacts] = useState<InspectorListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(initialFileId);
  const [detail, setDetail] = useState<InspectorDetail | null>(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [busyAction, setBusyAction] = useState(false);
  const [testOutcome, setTestOutcome] = useState<{
    status: 'success' | 'denied' | 'tampered';
    title: string;
    detail: string;
  } | null>(null);

  async function loadList(preserveSelection = true) {
    setLoadingList(true);
    try {
      const res = await api.getInspectorFiles(token);
      setArtifacts(res.artifacts);
      if (initialFileId && res.artifacts.some((a) => a.id === initialFileId)) {
        setSelectedId(initialFileId);
      } else if (!preserveSelection || !selectedId || !res.artifacts.some((a) => a.id === selectedId)) {
        setSelectedId(res.artifacts[0]?.id ?? null);
      }
    } finally {
      setLoadingList(false);
    }
  }

  async function loadDetail(fileId: string) {
    setLoadingDetail(true);
    try {
      const res = await api.getInspectorDetail(token, fileId);
      setDetail(res.artifact);
    } finally {
      setLoadingDetail(false);
    }
  }

  useEffect(() => {
    void loadList(true);
  }, [token, initialFileId]);

  useEffect(() => {
    if (selectedId) {
      setTestOutcome(null);
      void loadDetail(selectedId);
    } else {
      setDetail(null);
    }
  }, [selectedId, token]);

  async function handleSimulateTamper() {
    if (!detail) return;
    setBusyAction(true);
    setTestOutcome(null);
    try {
      await api.simulateTamper(token, detail.id);
      await Promise.all([loadDetail(detail.id), loadList(true)]);
      onDiskChanged();
    } catch (err) {
      setTestOutcome({
        status: 'denied',
        title: 'Tamper simulation blocked',
        detail: err instanceof ApiError ? err.message : 'Operation failed.',
      });
    } finally {
      setBusyAction(false);
    }
  }

  async function handleRestore() {
    if (!detail) return;
    setBusyAction(true);
    setTestOutcome(null);
    try {
      await api.restoreTamper(token, detail.id);
      await Promise.all([loadDetail(detail.id), loadList(true)]);
      onDiskChanged();
    } catch (err) {
      setTestOutcome({
        status: 'denied',
        title: 'Restore failed',
        detail: err instanceof ApiError ? err.message : 'Operation failed.',
      });
    } finally {
      setBusyAction(false);
    }
  }

  async function handleTestDownload() {
    if (!detail) return;
    setBusyAction(true);
    setTestOutcome(null);
    try {
      await api.downloadFile(token, detail.id, detail.original_name);
      setTestOutcome({
        status: 'success',
        title: 'HTTP 200 OK — Authorized & Integrity Verified',
        detail:
          'JWT, ACL authorization, SHA-256 ciphertext hash, and AES-256-GCM auth tag succeeded. Plaintext served cleanly.',
      });
    } catch (err) {
      if (err instanceof ApiError) {
        setTestOutcome({
          status: err.status === 422 ? 'tampered' : 'denied',
          title:
            err.status === 422
              ? 'HTTP 422 — Integrity Verification Failure'
              : `HTTP ${err.status} — Access Denied`,
          detail: err.message,
        });
      }
    } finally {
      setBusyAction(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold text-[#F1F5F9]">
          Security Inspector &amp; Disk Tamper Lab
        </h1>
        <p className="mt-1 text-sm text-[#94A3B8]">
          Inspect raw AES-256-GCM ciphertext stored on disk, verify cryptographic metadata, and
          simulate 1-byte storage tampering to test integrity enforcement.
        </p>
      </div>

      {loadingList ? (
        <div className="bg-[#111A2E] border border-[#24324F] rounded-xl p-8 animate-pulse h-64" />
      ) : artifacts.length === 0 ? (
        <div className="bg-[#111A2E] border border-[#24324F] rounded-xl px-6 py-14 text-center">
          <p className="text-sm font-medium text-[#F1F5F9]">No encrypted artifacts on disk</p>
          <p className="mt-1 text-xs text-[#94A3B8]">
            Upload a file in My Vault to inspect its ciphertext hex dump and cryptographic metadata.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Artifact Selector List */}
          <div className="lg:col-span-4 bg-[#111A2E] border border-[#24324F] rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-[#24324F] text-xs font-medium text-[#94A3B8]">
              Encrypted Disk Blobs ({artifacts.length})
            </div>
            <div className="divide-y divide-[#24324F]">
              {artifacts.map((item) => {
                const isSelected = item.id === selectedId;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setSelectedId(item.id)}
                    className={`w-full text-left px-4 py-3 transition-colors ${
                      isSelected ? 'bg-[#17223B]' : 'hover:bg-[#17223B]/50'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium text-[#F1F5F9] truncate">
                        {item.original_name}
                      </span>
                      {item.is_intact ? (
                        <span className="text-xs font-medium text-[#10B981] shrink-0">Intact</span>
                      ) : (
                        <span className="text-xs font-medium text-[#EF4444] shrink-0">Tampered</span>
                      )}
                    </div>
                    <div className="mt-1 text-xs text-[#94A3B8]">
                      Owner {item.owner_username} <span aria-hidden="true">·</span>{' '}
                      {item.is_authorized_for_download ? 'Authorized' : 'No ACL grant'}
                    </div>
                    <div className="mt-0.5 text-xs font-mono text-[#64748B] truncate">
                      {item.storage_filename}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Detail & Ciphertext Hex Dump */}
          <div className="lg:col-span-8 space-y-6">
            {loadingDetail || !detail ? (
              <div className="bg-[#111A2E] border border-[#24324F] rounded-xl p-8 animate-pulse h-96" />
            ) : (
              <>
                <div className="bg-[#111A2E] border border-[#24324F] rounded-xl p-6 space-y-5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <HardDrive className="w-4 h-4 text-[#3B82F6]" />
                        <h2 className="font-display text-base font-semibold text-[#F1F5F9]">
                          {detail.original_name}
                        </h2>
                      </div>
                      <div className="mt-1 text-xs text-[#94A3B8] font-mono">
                        {detail.storage_path_display} <span aria-hidden="true">·</span>{' '}
                        <span className="tabular-nums">{detail.encrypted_bytes}</span> encrypted bytes
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {detail.is_intact ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#10B981]">
                          <CheckCircle2 className="w-4 h-4" />
                          SHA-256 Verified
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#EF4444]">
                          <AlertTriangle className="w-4 h-4" />
                          Disk Integrity Mismatch
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Cryptographic Metadata Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-[#24324F] text-xs font-mono tabular-nums">
                    <div>
                      <div className="font-sans text-[#94A3B8] mb-1">96-Bit AES-GCM IV</div>
                      <div className="text-[#F1F5F9] break-all">{detail.iv_hex}</div>
                    </div>
                    <div>
                      <div className="font-sans text-[#94A3B8] mb-1">128-Bit GCM Auth Tag</div>
                      <div className="text-[#F1F5F9] break-all">{detail.auth_tag_hex}</div>
                    </div>
                    <div className="sm:col-span-2">
                      <div className="font-sans text-[#94A3B8] mb-1">
                        Stored Expected SHA-256 Digest
                      </div>
                      <div className="text-[#CBD5E1] break-all">{detail.stored_sha256}</div>
                    </div>
                    <div className="sm:col-span-2">
                      <div className="font-sans text-[#94A3B8] mb-1">
                        Live Computed Disk SHA-256 Digest
                      </div>
                      <div
                        className={`break-all ${
                          detail.is_intact ? 'text-[#10B981]' : 'text-[#EF4444]'
                        }`}
                      >
                        {detail.current_sha256}
                      </div>
                    </div>
                  </div>

                  {/* Interactive Demo Actions */}
                  <div className="pt-4 border-t border-[#24324F] flex flex-wrap items-center gap-3">
                    <button
                      type="button"
                      disabled={busyAction}
                      onClick={handleTestDownload}
                      className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-xs font-medium text-white transition-colors disabled:opacity-50 whitespace-nowrap"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Test Verified Download
                    </button>

                    {detail.can_simulate_tamper && detail.is_intact && (
                      <button
                        type="button"
                        disabled={busyAction}
                        onClick={handleSimulateTamper}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#17223B] hover:bg-[#EF4444]/15 border border-[#EF4444]/40 text-xs font-medium text-[#FCA5A5] transition-colors disabled:opacity-50 whitespace-nowrap"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        Simulate 1-Byte Disk Tamper
                      </button>
                    )}

                    {detail.can_simulate_tamper && detail.is_tamper_backup_present && (
                      <button
                        type="button"
                        disabled={busyAction}
                        onClick={handleRestore}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#17223B] hover:bg-[#10B981]/15 border border-[#10B981]/40 text-xs font-medium text-[#6EE7B7] transition-colors disabled:opacity-50 whitespace-nowrap"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        Restore Original Ciphertext
                      </button>
                    )}

                    {!detail.can_simulate_tamper && (
                      <span className="text-xs text-[#94A3B8]">
                        Only the file owner ({detail.owner_username}) or an Admin can mutate disk bytes.
                      </span>
                    )}
                  </div>

                  {testOutcome && (
                    <div
                      role="status"
                      className={`px-4 py-3 rounded-lg border text-xs ${
                        testOutcome.status === 'success'
                          ? 'bg-[#10B981]/10 border-[#10B981]/30 text-[#D1FAE5]'
                          : 'bg-[#EF4444]/10 border-[#EF4444]/40 text-[#FECACA]'
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        {testOutcome.status === 'success' ? (
                          <CheckCircle2 className="w-4 h-4 text-[#10B981] shrink-0 mt-0.5" />
                        ) : (
                          <ShieldAlert className="w-4 h-4 text-[#EF4444] shrink-0 mt-0.5" />
                        )}
                        <div>
                          <div className="font-medium">{testOutcome.title}</div>
                          <div className="mt-0.5 opacity-90">{testOutcome.detail}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Raw Ciphertext Hex Dump */}
                <div className="bg-[#111A2E] border border-[#24324F] rounded-xl overflow-hidden">
                  <div className="px-5 py-3.5 border-b border-[#24324F] flex items-center justify-between gap-4">
                    <span className="text-xs font-medium text-[#F1F5F9]">
                      Raw Stored Ciphertext Preview (First 384 Bytes)
                    </span>
                    <span className="text-xs text-[#94A3B8]">
                      Unreadable encrypted bytes persisted in PostgreSQL bytea storage
                    </span>
                  </div>
                  <div className="p-4 bg-[#0B1120] overflow-x-auto font-mono text-xs leading-6 tabular-nums">
                    {detail.hex_dump.map((row) => (
                      <div key={row.offset} className="flex items-center gap-5 whitespace-pre">
                        <span className="text-[#64748B]">{row.offset}</span>
                        <span className="text-[#93C5FD] min-w-[345px]">{row.hex}</span>
                        <span className="text-[#94A3B8]">{row.ascii}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
