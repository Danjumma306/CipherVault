import { useCallback, useEffect, useState } from 'react';
import { onAuthStateChanged, signOut } from 'firebase/auth';
import {
  Activity,
  FileKey2,
  FolderLock,
  LogOut,
  Menu,
  Microscope,
  Share2,
  X,
} from 'lucide-react';
import { api } from './api';
import { AuditLogView } from './components/AuditLogView';
import { AuthGateway } from './components/AuthGateway';
import { OperatorGate } from './components/OperatorGate';
import { SecurityInspectorView } from './components/SecurityInspectorView';
import { ShareDrawer } from './components/ShareDrawer';
import { VaultView } from './components/VaultView';
import { auth } from './lib/firebase';
import type { ActiveView, User, VaultFile } from './types';

const OPERATOR_GATE_PATH = '/ops-gate-7f3a';

const VIEW_LABELS: Record<ActiveView, string> = {
  vault: 'My Vault',
  shared: 'Shared With Me',
  inspector: 'Security Inspector',
  audit: 'Audit Log',
};

export default function App() {
  // Store auth tokens strictly in memory (never in localStorage)
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [initializing, setInitializing] = useState<boolean>(true);
  const [isOperatorGate, setIsOperatorGate] = useState<boolean>(
    () => window.location.pathname === OPERATOR_GATE_PATH,
  );
  const [activeView, setActiveView] = useState<ActiveView>('vault');
  const [ownedFiles, setOwnedFiles] = useState<VaultFile[]>([]);
  const [sharedFiles, setSharedFiles] = useState<VaultFile[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [shareFileId, setShareFileId] = useState<string | null>(null);
  const [inspectorFileId, setInspectorFileId] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleLogout = useCallback(async () => {
    try {
      if (auth.currentUser) {
        await signOut(auth);
      }
    } catch {
      // Ignore Firebase signOut errors
    }
    setToken(null);
    setUser(null);
    setOwnedFiles([]);
    setSharedFiles([]);
    setShareFileId(null);
    setInspectorFileId(null);
    setActiveView('vault');
  }, []);

  const refreshFiles = useCallback(
    async (activeToken?: string) => {
      const authToken = activeToken ?? token;
      if (!authToken) return;
      setLoadingFiles(true);
      try {
        const res = await api.getFiles(authToken);
        setOwnedFiles(res.ownedFiles);
        setSharedFiles(res.sharedFiles);
      } catch {
        // Handled by auth layer
      } finally {
        setLoadingFiles(false);
      }
    },
    [token],
  );

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        try {
          const idToken = await firebaseUser.getIdToken();
          const me = await api.getMe(idToken);
          setToken(idToken);
          setUser(me.user);
          if (window.location.pathname === OPERATOR_GATE_PATH) {
            window.history.replaceState({}, '', '/');
            setIsOperatorGate(false);
          }
          await refreshFiles(idToken);
        } catch {
          await signOut(auth).catch(() => {});
        }
      }
      setInitializing(false);
    });
    return () => unsubscribe();
  }, [refreshFiles]);

  function handleAuthenticated(newToken: string, authedUser: User) {
    setToken(newToken);
    setUser(authedUser);
    if (window.location.pathname === OPERATOR_GATE_PATH) {
      window.history.replaceState({}, '', '/');
      setIsOperatorGate(false);
    }
    void refreshFiles(newToken);
  }

  if (initializing) {
    return (
      <div className="min-h-screen bg-[#0B1120] flex items-center justify-center text-sm text-[#94A3B8]">
        Verifying session...
      </div>
    );
  }

  if (!token || !user) {
    if (isOperatorGate) {
      return (
        <OperatorGate
          onAuthenticated={handleAuthenticated}
          onReturnStandard={() => {
            window.history.replaceState({}, '', '/');
            setIsOperatorGate(false);
          }}
        />
      );
    }
    return <AuthGateway onAuthenticated={handleAuthenticated} />;
  }

  const activeShareFile = ownedFiles.find((f) => f.id === shareFileId) ?? null;

  const navItems: Array<{ id: ActiveView; label: string; icon: typeof FolderLock }> = [
    { id: 'vault', label: 'My Vault', icon: FolderLock },
    { id: 'shared', label: 'Shared With Me', icon: Share2 },
    { id: 'inspector', label: 'Security Inspector', icon: Microscope },
    { id: 'audit', label: 'Audit Log', icon: Activity },
  ];

  return (
    <div className="min-h-screen bg-[#0B1120] text-[#F1F5F9] flex">
      {/* Desktop Left Sidebar */}
      <aside className="hidden lg:flex w-64 shrink-0 flex-col justify-between bg-[#111A2E] border-r border-[#24324F]">
        <div>
          <div className="h-16 px-6 border-b border-[#24324F] flex items-center gap-2.5">
            <FileKey2 className="w-5 h-5 text-[#3B82F6]" />
            <span className="font-display font-semibold text-base tracking-tight text-[#F1F5F9] whitespace-nowrap">
              CipherVault
            </span>
          </div>

          <nav className="p-4 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveView(item.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-[#17223B] text-[#F1F5F9] border border-[#24324F]'
                      : 'text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#17223B]/50 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-[#3B82F6]' : ''}`} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-4 border-t border-[#24324F] text-xs text-[#94A3B8]">
          <div className="font-medium text-[#F1F5F9] truncate">{user.username}</div>
          <div className="mt-0.5 truncate">{user.email}</div>
        </div>
      </aside>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="w-64 bg-[#111A2E] border-r border-[#24324F] h-full flex flex-col justify-between">
            <div>
              <div className="h-16 px-5 border-b border-[#24324F] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileKey2 className="w-5 h-5 text-[#3B82F6]" />
                  <span className="font-display font-semibold text-base text-[#F1F5F9]">
                    CipherVault
                  </span>
                </div>
                <button
                  type="button"
                  aria-label="Close navigation menu"
                  onClick={() => setMobileMenuOpen(false)}
                  className="p-1.5 text-[#94A3B8] hover:text-[#F1F5F9]"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <nav className="p-4 space-y-1">
                {navItems.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeView === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setActiveView(item.id);
                        setMobileMenuOpen(false);
                      }}
                      className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium ${
                        isActive
                          ? 'bg-[#17223B] text-[#F1F5F9]'
                          : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                      {item.label}
                    </button>
                  );
                })}
              </nav>
            </div>
            <div className="p-4 border-t border-[#24324F] text-xs text-[#94A3B8]">
              <div className="font-medium text-[#F1F5F9] truncate">{user.username}</div>
              <div className="mt-0.5 truncate">{user.email}</div>
            </div>
          </div>
          <div className="flex-1 bg-black/60" onClick={() => setMobileMenuOpen(false)} />
        </div>
      )}

      {/* Main Content Shell */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 px-6 border-b border-[#24324F] bg-[#0B1120] flex items-center justify-between gap-8 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 rounded-lg border border-[#24324F] text-[#94A3B8] hover:text-[#F1F5F9]"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2 text-sm truncate">
              <span className="text-[#94A3B8]">CipherVault</span>
              <span className="text-[#64748B]" aria-hidden="true">
                /
              </span>
              <span className="font-medium text-[#F1F5F9] truncate">
                {VIEW_LABELS[activeView]}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4 shrink-0">
            <div className="hidden sm:flex items-center gap-2 text-xs text-[#94A3B8] whitespace-nowrap">
              <span className="font-medium text-[#F1F5F9]">{user.username}</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono text-[#3B82F6]">{user.role}</span>
            </div>
            <button
              type="button"
              onClick={() => void handleLogout()}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#111A2E] hover:bg-[#17223B] border border-[#24324F] text-xs font-medium text-[#F1F5F9] transition-colors whitespace-nowrap shrink-0"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        </header>

        <main className="flex-1 p-6 lg:p-8 max-w-6xl w-full mx-auto">
          {activeView === 'vault' && (
            <VaultView
              mode="owned"
              user={user}
              token={token}
              files={ownedFiles}
              loading={loadingFiles}
              onRefresh={() => void refreshFiles()}
              onOpenShare={(f) => setShareFileId(f.id)}
              onOpenInspector={(fileId) => {
                setInspectorFileId(fileId);
                setActiveView('inspector');
              }}
            />
          )}

          {activeView === 'shared' && (
            <VaultView
              mode="shared"
              user={user}
              token={token}
              files={sharedFiles}
              loading={loadingFiles}
              onRefresh={() => void refreshFiles()}
              onOpenShare={(f) => setShareFileId(f.id)}
              onOpenInspector={(fileId) => {
                setInspectorFileId(fileId);
                setActiveView('inspector');
              }}
            />
          )}

          {activeView === 'inspector' && (
            <SecurityInspectorView
              token={token}
              initialFileId={inspectorFileId}
              onDiskChanged={() => void refreshFiles()}
            />
          )}

          {activeView === 'audit' && (
            <AuditLogView
              token={token}
              currentUser={user}
              onUserUpdated={() => {
                api
                  .getMe(token)
                  .then((res) => setUser(res.user))
                  .catch(() => {});
              }}
            />
          )}
        </main>
      </div>

      <ShareDrawer
        file={activeShareFile}
        token={token}
        currentUserId={user.id}
        onClose={() => setShareFileId(null)}
        onUpdated={() => void refreshFiles()}
      />
    </div>
  );
}
