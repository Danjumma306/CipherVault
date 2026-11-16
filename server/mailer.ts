import nodemailer from 'nodemailer';

export interface OtpMailResult {
  delivery: 'smtp' | 'ethereal' | 'dev-fallback';
  previewUrl?: string;
  devOtp?: string;
}

export async function sendOtpVerificationEmail(params: {
  toEmail: string;
  username: string;
  otp: string;
  expiresMinutes: number;
}): Promise<OtpMailResult> {
  const subject = 'CipherVault — Verify Your Email Address';
  const textBody = [
    `Hello ${params.username},`,
    '',
    `Your CipherVault email verification code is: ${params.otp}`,
    '',
    `This code expires in ${params.expiresMinutes} minutes.`,
    'If you did not create a CipherVault account, you can safely ignore this message.',
  ].join('\n');

  const htmlBody = `
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; color: #0f172a;">
      <h2 style="margin-bottom: 8px;">Verify your CipherVault email</h2>
      <p style="font-size: 14px; color: #334155;">Hello <strong>${params.username}</strong>,</p>
      <p style="font-size: 14px; color: #334155;">Enter the 6-digit verification code below to activate your account and return to sign in:</p>
      <div style="margin: 20px 0; padding: 14px 20px; background: #0b1120; color: #f8fafc; font-family: monospace; font-size: 28px; letter-spacing: 6px; border-radius: 8px; text-align: center;">
        ${params.otp}
      </div>
      <p style="font-size: 12px; color: #64748b;">This code expires in ${params.expiresMinutes} minutes. Never share this code with anyone.</p>
    </div>
  `;

  const cleanEnv = (val?: string) => val?.trim().replace(/^["']|["']$/g, '') || '';

  const smtpHost = cleanEnv(process.env.SMTP_HOST);
  const smtpUser = cleanEnv(process.env.SMTP_USER);
  const smtpPass = cleanEnv(process.env.SMTP_PASS);

  if (smtpHost && smtpUser && smtpPass) {
    const port = Number(cleanEnv(process.env.SMTP_PORT) || '587');
    const secureRaw = cleanEnv(process.env.SMTP_SECURE).toLowerCase();
    const secure = secureRaw === 'true' || port === 465;
    const configuredFrom = cleanEnv(process.env.SMTP_FROM);

    if (!configuredFrom && !smtpUser.includes('@')) {
      throw new Error(
        'SMTP_FROM must be set to your verified sender email (e.g. "CipherVault <you@domain.com>") when using a non-email SMTP_USER.',
      );
    }

    const from = configuredFrom || `CipherVault <${smtpUser}>`;

    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port,
      secure,
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    });

    await transporter.sendMail({
      from,
      to: params.toEmail,
      subject,
      text: textBody,
      html: htmlBody,
    });

    return { delivery: 'smtp' };
  }

  // Fallback when SMTP_* is not configured: attempt Ethereal test SMTP inbox
  try {
    const testAccount = await nodemailer.createTestAccount();
    const transporter = nodemailer.createTransport({
      host: testAccount.smtp.host,
      port: testAccount.smtp.port,
      secure: testAccount.smtp.secure,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });

    const info = await transporter.sendMail({
      from: 'CipherVault <no-reply@ciphervault.edu>',
      to: params.toEmail,
      subject,
      text: textBody,
      html: htmlBody,
    });

    const previewUrl = nodemailer.getTestMessageUrl(info) || undefined;
    return { delivery: 'ethereal', previewUrl };
  } catch (err) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[CipherVault Mailer] SMTP not configured and Ethereal unavailable; using dev fallback:', err);
      return { delivery: 'dev-fallback', devOtp: params.otp };
    }
    throw new Error(
      'Outbound email service (SMTP_HOST, SMTP_USER, SMTP_PASS) is not configured.',
      { cause: err },
    );
  }
}
