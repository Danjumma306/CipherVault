import { useState } from 'react';
import { signInWithPopup, signOut } from 'firebase/auth';
import { ArrowLeft, KeyRound, Shield } from 'lucide-react';
import { api, ApiError } from '../api';
import { auth, googleAuthProvider } from '../lib/firebase';
import type { User } from '../types';

interface OperatorGateProps {
  onAuthenticated: (token: string, user: User) => void;
  onReturnStandard: () => void;
}

export function OperatorGate({ onAuthenticated, onReturnStandard }: OperatorGateProps) {
  const [useLocalPasskey, setUseLocalPasskey] = useState(false);
  const [email, setEmail] = useState('');
  const [passkey, setPasskey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleGoogleOperatorAuth() {
    setError(null);
    setLoading(true);
    try {
      const credential = await signInWithPopup(auth, googleAuthProvider);
      const idToken = await credential.user.getIdToken();
      const verified = await api.verifyOperatorGoogle(idToken);
      onAuthenticated(idToken, verified.user);
    } catch (err) {
      if (auth.currentUser) {
        await signOut(auth).catch(() => {});
      }
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        const code = (err as { code?: string } | null)?.code;
        if (code === 'auth/popup-closed-by-user') {
          setError(
            'Google sign-in popup was closed before completing authentication. Please try again and allow popups for this site (or open this URL directly in its own browser tab).',
          );
        } else if (code === 'auth/popup-blocked') {
          setError(
            'Your browser blocked the Google sign-in popup. Allow popups for this site and click Authenticate with Google again.',
          );
        } else if (code === 'auth/unauthorized-domain') {
          setError(
            'This hostname is not listed under Firebase Authorized Domains. Use the deployed Cloud Run URL or the offline operator passkey.',
          );
        } else {
          setError(err instanceof Error ? err.message : 'Operator authentication failed.');
        }
      }
    } finally {
      setLoading(false);
    }
  }

  async function handlePasskeyAuth(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await api.loginOperatorPasskey(email, passkey);
      onAuthenticated(result.token, result.user);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Operator authentication failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#0B1120] text-[#F1F5F9] flex flex-col justify-center px-6 py-12">
      <div className="max-w-md w-full mx-auto bg-[#111A2E] border border-[#24324F] rounded-xl p-8">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5 text-[#3B82F6]">
            <Shield className="w-5 h-5" />
            <span className="font-display font-semibold text-base text-[#F1F5F9]">
              Operator Gate
            </span>
          </div>
          <button
            type="button"
            onClick={onReturnStandard}
            className="inline-flex items-center gap-1.5 text-xs text-[#94A3B8] hover:text-[#F1F5F9]"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Standard Portal
          </button>
        </div>

        <h1 className="mt-6 font-display text-xl font-semibold text-[#F1F5F9]">
          Restricted Administrator Access
        </h1>
        <p className="mt-1.5 text-xs leading-relaxed text-[#94A3B8]">
          Requires verified identity matching the configured system administrator account. Standard
          password credentials are rejected on this channel.
        </p>

        {error && (
          <div
            role="alert"
            className="mt-5 px-4 py-3 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/40 text-xs text-[#FCA5A5]"
          >
            {error}
          </div>
        )}

        {!useLocalPasskey ? (
          <div className="mt-6 space-y-4">
            <button
              type="button"
              disabled={loading}
              onClick={handleGoogleOperatorAuth}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-sm font-medium text-white transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              {loading ? 'Verifying Identity...' : 'Authenticate with Google'}
            </button>

            <button
              type="button"
              onClick={() => {
                setUseLocalPasskey(true);
                setError(null);
              }}
              className="w-full text-center text-xs text-[#94A3B8] hover:text-[#F1F5F9] py-1"
            >
              Use offline operator passkey instead
            </button>
          </div>
        ) : (
          <form onSubmit={handlePasskeyAuth} className="mt-6 space-y-4">
            <div>
              <label htmlFor="op-email" className="block text-xs font-medium text-[#CBD5E1] mb-1.5">
                Administrator Email
              </label>
              <input
                id="op-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin email"
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#0B1120] border border-[#24324F] text-sm text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#3B82F6]"
              />
            </div>

            <div>
              <label htmlFor="op-passkey" className="block text-xs font-medium text-[#CBD5E1] mb-1.5">
                Operator Passkey
              </label>
              <input
                id="op-passkey"
                type="password"
                required
                value={passkey}
                onChange={(e) => setPasskey(e.target.value)}
                placeholder="ADMIN_PASSKEY"
                className="w-full px-3.5 py-2.5 rounded-lg bg-[#0B1120] border border-[#24324F] text-sm text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#3B82F6]"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-sm font-medium text-white transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              <KeyRound className="w-4 h-4" />
              {loading ? 'Verifying Passkey...' : 'Verify Operator Passkey'}
            </button>

            <button
              type="button"
              onClick={() => {
                setUseLocalPasskey(false);
                setError(null);
              }}
              className="w-full text-center text-xs text-[#94A3B8] hover:text-[#F1F5F9] py-1"
            >
              Return to Google authentication
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
