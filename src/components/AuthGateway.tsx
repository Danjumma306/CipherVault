import { useMemo, useState } from 'react';
import {
  ArrowLeft,
  Check,
  ExternalLink,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  MailCheck,
  RefreshCw,
  ShieldCheck,
  UserPlus,
  X,
} from 'lucide-react';
import { api, ApiError, type RegisterOtpResponse } from '../api';
import type { User } from '../types';

interface AuthGatewayProps {
  onAuthenticated: (token: string, user: User) => void;
}

interface PasswordAnalysis {
  checks: Array<{ id: string; label: string; met: boolean }>;
  passedCount: number;
  scoreLabel: 'Very Weak' | 'Weak' | 'Fair' | 'Strong';
  isStrong: boolean;
}

function analyzePassword(password: string, username: string, email: string): PasswordAnalysis {
  const lower = password.toLowerCase();
  const cleanUser = username.trim().toLowerCase();
  const emailLocal = email.trim().split('@')[0]?.toLowerCase() ?? '';

  const noIdentityLeak =
    password.length > 0 &&
    !(cleanUser.length >= 3 && lower.includes(cleanUser)) &&
    !(emailLocal.length >= 3 && lower.includes(emailLocal));

  const checks = [
    { id: 'len', label: 'At least 12 characters', met: password.length >= 12 },
    { id: 'upper', label: 'Uppercase letter (A-Z)', met: /[A-Z]/.test(password) },
    { id: 'lower', label: 'Lowercase letter (a-z)', met: /[a-z]/.test(password) },
    { id: 'num', label: 'Number (0-9)', met: /[0-9]/.test(password) },
    { id: 'sym', label: 'Special character (!@#$...)', met: /[^A-Za-z0-9]/.test(password) },
    { id: 'id', label: 'Excludes username & email', met: noIdentityLeak },
  ];

  const passedCount = checks.filter((c) => c.met).length;
  const isStrong = passedCount === checks.length;

  let scoreLabel: PasswordAnalysis['scoreLabel'] = 'Very Weak';
  if (isStrong) {
    scoreLabel = 'Strong';
  } else if (passedCount >= 4) {
    scoreLabel = 'Fair';
  } else if (passedCount >= 2) {
    scoreLabel = 'Weak';
  }

  return { checks, passedCount, scoreLabel, isStrong };
}

export function AuthGateway({ onAuthenticated }: AuthGatewayProps) {
  const [mode, setMode] = useState<'login' | 'register' | 'verify-otp'>('login');
  const [identifier, setIdentifier] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const [pendingEmail, setPendingEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [deliveryInfo, setDeliveryInfo] = useState<RegisterOtpResponse | null>(null);
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);

  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const passwordAnalysis = useMemo(
    () => analyzePassword(password, username, email),
    [password, username, email],
  );

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setUnverifiedEmail(null);

    if (mode === 'register' && !passwordAnalysis.isStrong) {
      setError('Please choose a strong password that satisfies every security requirement.');
      return;
    }

    if (mode === 'verify-otp') {
      const cleanOtp = otp.trim();
      if (!/^\d{6}$/.test(cleanOtp)) {
        setError('Enter the 6-digit numeric verification code sent to your email.');
        return;
      }

      setLoading(true);
      try {
        await api.verifyOtp(pendingEmail, cleanOtp);
        setMode('login');
        setIdentifier(pendingEmail);
        setPassword('');
        setOtp('');
        setPendingEmail('');
        setDeliveryInfo(null);
        setNotice(
          'Email verified! Sign in with your username or email and password to access your vault.',
        );
      } catch (err) {
        setError(err instanceof ApiError ? err.message : 'Verification failed.');
      } finally {
        setLoading(false);
      }
      return;
    }

    setLoading(true);
    try {
      if (mode === 'login') {
        const result = await api.login(identifier, password);
        onAuthenticated(result.token, result.user);
      } else {
        const regResult = await api.register(username, email, password);
        setPendingEmail(regResult.email);
        setDeliveryInfo(regResult);
        setOtp('');
        setPassword('');
        setMode('verify-otp');
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        if (err.code === 'EMAIL_NOT_VERIFIED' && err.email) {
          setUnverifiedEmail(err.email);
        }
      } else {
        setError('Authentication request failed.');
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleResendOtp(targetEmail?: string) {
    const emailToSend = (targetEmail ?? pendingEmail).trim();
    if (!emailToSend) return;

    setError(null);
    setNotice(null);
    setResending(true);
    try {
      const res = await api.resendOtp(emailToSend);
      setPendingEmail(res.email);
      setDeliveryInfo(res);
      setOtp('');
      setUnverifiedEmail(null);
      setMode('verify-otp');
      setNotice(`A fresh 6-digit verification code was sent to ${res.email}.`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not resend verification code.');
    } finally {
      setResending(false);
    }
  }

  const strengthColor =
    passwordAnalysis.scoreLabel === 'Strong'
      ? 'bg-[#10B981]'
      : passwordAnalysis.scoreLabel === 'Fair'
        ? 'bg-[#F59E0B]'
        : 'bg-[#EF4444]';

  const strengthTextColor =
    passwordAnalysis.scoreLabel === 'Strong'
      ? 'text-[#10B981]'
      : passwordAnalysis.scoreLabel === 'Fair'
        ? 'text-[#F59E0B]'
        : 'text-[#EF4444]';

  const activeBars =
    password.length === 0
      ? 0
      : passwordAnalysis.scoreLabel === 'Strong'
        ? 4
        : passwordAnalysis.scoreLabel === 'Fair'
          ? 3
          : passwordAnalysis.scoreLabel === 'Weak'
            ? 2
            : 1;

  return (
    <div className="min-h-screen bg-[#0B1120] text-[#F1F5F9] flex flex-col justify-center px-6 py-12">
      <div className="max-w-5xl w-full mx-auto grid grid-cols-1 lg:grid-cols-12 gap-10 items-stretch">
        {/* Left Cryptographic Security Overview */}
        <div className="lg:col-span-6 flex flex-col justify-between bg-[#111A2E] border border-[#24324F] rounded-xl p-8">
          <div>
            <div className="flex items-center gap-2.5 text-[#3B82F6]">
              <Lock className="w-5 h-5" />
              <span className="font-display font-semibold tracking-tight text-lg text-[#F1F5F9]">
                CipherVault
              </span>
            </div>

            <h1 className="mt-6 font-display text-3xl font-semibold tracking-tight text-[#F1F5F9] text-balance">
              Zero-Trust Encrypted File Storage &amp; Access Control
            </h1>
            <p className="mt-3 text-sm leading-relaxed text-[#94A3B8]">
              Every uploaded file is encrypted in memory with AES-256-GCM before persistence in
              PostgreSQL, indexed by a SHA-256 integrity digest, and protected by email-verified
              credentials, bcrypt hashing, and per-file Access Control Lists.
            </p>

            <div className="mt-8 pt-6 border-t border-[#24324F] grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div>
                <div className="font-medium text-[#F1F5F9]">Confidentiality at Rest</div>
                <div className="mt-1 text-[#94A3B8]">
                  AES-256-GCM with 96-bit random IVs and per-file HKDF-SHA256 keys.
                </div>
              </div>
              <div>
                <div className="font-medium text-[#F1F5F9]">Integrity Verification</div>
                <div className="mt-1 text-[#94A3B8]">
                  Constant-time SHA-256 digest and GCM tag check prior to decryption.
                </div>
              </div>
              <div>
                <div className="font-medium text-[#F1F5F9]">Email OTP + Strong Password</div>
                <div className="mt-1 text-[#94A3B8]">
                  12+ character complex passwords with bcrypt (cost 12) and 6-digit email OTP.
                </div>
              </div>
              <div>
                <div className="font-medium text-[#F1F5F9]">Least-Privilege ACLs</div>
                <div className="mt-1 text-[#94A3B8]">
                  Strict account isolation with explicit per-file sharing permissions.
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8 pt-6 border-t border-[#24324F] text-xs text-[#94A3B8]">
            Sessions are issued as short-lived signed JWTs held strictly in memory. New accounts
            must complete email OTP verification before signing in.
          </div>
        </div>

        {/* Right Authentication Form */}
        <div className="lg:col-span-6 bg-[#111A2E] border border-[#24324F] rounded-xl p-8 flex flex-col justify-center">
          {mode !== 'verify-otp' && (
            <div className="flex items-center gap-1 p-1 bg-[#0B1120] border border-[#24324F] rounded-lg w-fit">
              <button
                type="button"
                onClick={() => {
                  setMode('login');
                  setError(null);
                  setNotice(null);
                  setUnverifiedEmail(null);
                }}
                className={`px-4 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  mode === 'login'
                    ? 'bg-[#17223B] text-[#F1F5F9]'
                    : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode('register');
                  setError(null);
                  setNotice(null);
                  setUnverifiedEmail(null);
                }}
                className={`px-4 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  mode === 'register'
                    ? 'bg-[#17223B] text-[#F1F5F9]'
                    : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                }`}
              >
                Create Account
              </button>
            </div>
          )}

          <h2 className="mt-6 font-display text-xl font-semibold text-[#F1F5F9]">
            {mode === 'login'
              ? 'Sign in to your vault'
              : mode === 'register'
                ? 'Register a new member account'
                : 'Verify your email address'}
          </h2>
          <p className="mt-1 text-sm text-[#94A3B8]">
            {mode === 'login'
              ? 'Enter your verified credentials to receive a signed JWT session token.'
              : mode === 'register'
                ? 'Choose a strong password. You will verify your email via a 6-digit OTP before signing in.'
                : `Enter the 6-digit verification code sent to ${pendingEmail}.`}
          </p>

          {notice && (
            <div
              role="status"
              className="mt-5 px-4 py-3 rounded-lg bg-[#10B981]/10 border border-[#10B981]/40 text-sm text-[#6EE7B7]"
            >
              {notice}
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="mt-5 px-4 py-3 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/40 text-sm text-[#FCA5A5] space-y-2.5"
            >
              <div>{error}</div>
              {unverifiedEmail && mode === 'login' && (
                <button
                  type="button"
                  disabled={resending}
                  onClick={() => handleResendOtp(unverifiedEmail)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#17223B] border border-[#24324F] text-xs font-medium text-[#F1F5F9] hover:bg-[#1E293B] transition-colors disabled:opacity-50"
                >
                  <MailCheck className="w-3.5 h-3.5 text-[#3B82F6]" />
                  {resending ? 'Sending OTP...' : 'Verify Email Now'}
                </button>
              )}
            </div>
          )}

          {mode === 'verify-otp' && deliveryInfo && (
            <div className="mt-5 px-4 py-3 rounded-lg bg-[#0B1120] border border-[#24324F] text-xs text-[#CBD5E1] space-y-2">
              {deliveryInfo.delivery === 'smtp' && (
                <div>
                  A 6-digit OTP has been sent to{' '}
                  <span className="font-mono text-[#F1F5F9]">{pendingEmail}</span>. It expires in{' '}
                  <span className="font-mono">{deliveryInfo.expiresInMinutes}</span> minutes.
                </div>
              )}
              {deliveryInfo.delivery === 'ethereal' && (
                <div className="space-y-1.5">
                  <div>
                    Test email dispatched via Ethereal SMTP (expires in{' '}
                    <span className="font-mono">{deliveryInfo.expiresInMinutes}</span> minutes).
                  </div>
                  {deliveryInfo.previewUrl && (
                    <a
                      href={deliveryInfo.previewUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 text-[#3B82F6] hover:text-[#60A5FA] font-medium"
                    >
                      Open Ethereal Email Preview
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  )}
                </div>
              )}
              {deliveryInfo.delivery === 'dev-fallback' && deliveryInfo.devOtp && (
                <div>
                  SMTP is not configured in development mode. Use verification code:{' '}
                  <span className="font-mono font-semibold text-[#F1F5F9] tracking-widest">
                    {deliveryInfo.devOtp}
                  </span>
                </div>
              )}
            </div>
          )}

          <form onSubmit={handleSubmit} className="mt-6 space-y-4">
            {mode === 'verify-otp' ? (
              <div>
                <label
                  htmlFor="auth-otp"
                  className="block text-xs font-medium text-[#CBD5E1] mb-1.5"
                >
                  6-Digit Verification Code
                </label>
                <input
                  id="auth-otp"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  required
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  className="w-full px-3.5 py-3 rounded-lg bg-[#0B1120] border border-[#24324F] font-mono text-lg tracking-[0.45em] text-center text-[#F1F5F9] placeholder-[#475569] focus:outline-none focus:border-[#3B82F6] tabular-nums"
                />
              </div>
            ) : (
              <>
                {mode === 'login' ? (
                  <div>
                    <label
                      htmlFor="auth-identifier"
                      className="block text-xs font-medium text-[#CBD5E1] mb-1.5"
                    >
                      Username or Email
                    </label>
                    <input
                      id="auth-identifier"
                      type="text"
                      required
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      placeholder="username or email"
                      className="w-full px-3.5 py-2.5 rounded-lg bg-[#0B1120] border border-[#24324F] text-sm text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#3B82F6]"
                    />
                  </div>
                ) : (
                  <>
                    <div>
                      <label
                        htmlFor="auth-username"
                        className="block text-xs font-medium text-[#CBD5E1] mb-1.5"
                      >
                        Username
                      </label>
                      <input
                        id="auth-username"
                        type="text"
                        required
                        minLength={3}
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="minimum 3 characters"
                        className="w-full px-3.5 py-2.5 rounded-lg bg-[#0B1120] border border-[#24324F] text-sm text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#3B82F6]"
                      />
                    </div>
                    <div>
                      <label
                        htmlFor="auth-email"
                        className="block text-xs font-medium text-[#CBD5E1] mb-1.5"
                      >
                        Email Address
                      </label>
                      <input
                        id="auth-email"
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="name@example.com"
                        className="w-full px-3.5 py-2.5 rounded-lg bg-[#0B1120] border border-[#24324F] text-sm text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#3B82F6]"
                      />
                    </div>
                  </>
                )}

                <div>
                  <label
                    htmlFor="auth-password"
                    className="block text-xs font-medium text-[#CBD5E1] mb-1.5"
                  >
                    Password
                  </label>
                  <div className="relative">
                    <input
                      id="auth-password"
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder={
                        mode === 'register'
                          ? 'Minimum 12 characters with symbols'
                          : 'Enter password'
                      }
                      className="w-full pl-3.5 pr-10 py-2.5 rounded-lg bg-[#0B1120] border border-[#24324F] text-sm text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#3B82F6]"
                    />
                    <button
                      type="button"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      onClick={() => setShowPassword((prev) => !prev)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-[#94A3B8] hover:text-[#F1F5F9]"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Password Strength Checker (Register Mode) */}
                {mode === 'register' && (
                  <div className="p-4 rounded-lg bg-[#0B1120] border border-[#24324F] space-y-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-[#94A3B8]">Password Strength</span>
                      <span
                        className={`font-medium ${
                          password.length === 0 ? 'text-[#64748B]' : strengthTextColor
                        }`}
                      >
                        {password.length === 0 ? 'Required' : passwordAnalysis.scoreLabel}
                      </span>
                    </div>

                    <div className="grid grid-cols-4 gap-1.5">
                      {[1, 2, 3, 4].map((segment) => (
                        <div
                          key={segment}
                          className={`h-1.5 rounded-sm transition-colors ${
                            activeBars >= segment ? strengthColor : 'bg-[#1E293B]'
                          }`}
                        />
                      ))}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1 text-xs">
                      {passwordAnalysis.checks.map((item) => (
                        <div
                          key={item.id}
                          className={`flex items-center gap-1.5 ${
                            item.met ? 'text-[#10B981]' : 'text-[#94A3B8]'
                          }`}
                        >
                          {item.met ? (
                            <Check className="w-3.5 h-3.5 shrink-0" />
                          ) : (
                            <X className="w-3.5 h-3.5 shrink-0 text-[#64748B]" />
                          )}
                          <span>{item.label}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}

            <button
              type="submit"
              disabled={
                loading ||
                (mode === 'register' && !passwordAnalysis.isStrong) ||
                (mode === 'verify-otp' && otp.trim().length !== 6)
              }
              className="w-full mt-2 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#3B82F6] hover:bg-[#2563EB] text-sm font-medium text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            >
              {mode === 'login' ? (
                <>
                  <KeyRound className="w-4 h-4" />
                  {loading ? 'Verifying Credentials...' : 'Sign In & Issue JWT'}
                </>
              ) : mode === 'register' ? (
                <>
                  <UserPlus className="w-4 h-4" />
                  {loading
                    ? 'Creating & Sending OTP...'
                    : passwordAnalysis.isStrong
                      ? 'Create Account & Send Email OTP'
                      : 'Strong Password Required'}
                </>
              ) : (
                <>
                  <MailCheck className="w-4 h-4" />
                  {loading ? 'Verifying Code...' : 'Verify Email'}
                </>
              )}
            </button>

            {mode === 'verify-otp' && (
              <div className="flex items-center justify-between gap-3 pt-1">
                <button
                  type="button"
                  disabled={resending}
                  onClick={() => handleResendOtp()}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${resending ? 'animate-spin' : ''}`} />
                  {resending ? 'Resending Code...' : 'Resend Code'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMode('login');
                    setError(null);
                    setNotice(null);
                    setOtp('');
                  }}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] transition-colors"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  Back to Sign In
                </button>
              </div>
            )}
          </form>

          <div className="mt-6 pt-5 border-t border-[#24324F] flex items-center gap-2 text-xs text-[#94A3B8]">
            <ShieldCheck className="w-4 h-4 text-[#10B981] shrink-0" />
            <span>
              Public registration enforces email OTP verification and assigns least-privilege{' '}
              <span className="font-mono text-[#CBD5E1]">member</span> role.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
