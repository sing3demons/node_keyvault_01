// Outgoing email. SMTP (nodemailer) when SMTP_URL is set; otherwise messages are printed to the server log,
// which is only meant for local development.

import { createTransport, type Transporter } from "nodemailer";

export interface MailMessage {
  /** Sender ("Name <address>" or an address); the mailer's default when omitted. */
  from?: string;
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export interface Mailer {
  send(message: MailMessage): Promise<void>;
}

export class SmtpMailer implements Mailer {
  private readonly transport: Transporter;

  /** `url`: e.g. smtp://user:pass@smtp.example.com:587 or smtps://…:465 */
  constructor(
    url: string,
    private readonly from: string
  ) {
    this.transport = createTransport(url);
  }

  async send(m: MailMessage): Promise<void> {
    await this.transport.sendMail({ from: m.from ?? this.from, to: m.to, subject: m.subject, text: m.text, html: m.html });
  }
}

/** Development fallback: logs the message instead of sending it. */
export class ConsoleMailer implements Mailer {
  async send(m: MailMessage): Promise<void> {
    console.log(`\n[mail] from=${m.from ?? "(default)"} to=${m.to} subject="${m.subject}"\n${m.text}\n`);
  }
}

export function createMailer(settings: { smtpUrl?: string; from: string }): Mailer {
  if (settings.smtpUrl) return new SmtpMailer(settings.smtpUrl, settings.from);
  console.warn("SMTP_URL is not set — emails (verification codes) are printed to this log instead of being sent");
  return new ConsoleMailer();
}

/**
 * Valid sender for a From header: "Display Name <local@domain>" or "local@domain". No line breaks (header
 * injection) and no stray angle brackets.
 */
export function isValidSender(value: string): boolean {
  if (/[\r\n]/.test(value)) return false;
  const address = "[^\\s<>@\"]+@[^\\s<>@\"]+\\.[^\\s<>@\"]+";
  return new RegExp(`^(?:[^<>]{1,100}\\s*<${address}>|${address})$`).test(value.trim());
}
