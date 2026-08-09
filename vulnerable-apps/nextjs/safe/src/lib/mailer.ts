import nodemailer from "nodemailer";
import { RUNTIME_CONFIG } from "./config";

const transport = nodemailer.createTransport({
  host: RUNTIME_CONFIG.smtp.host,
  port: RUNTIME_CONFIG.smtp.port,
  secure: false,
});

export async function sendMail(to: string, subject: string, text: string): Promise<void> {
  try {
    await transport.sendMail({ from: "no-reply@bench.local", to, subject, text });
  } catch {
    // Mailpit may be absent; never block the flow in a benchmark.
  }
}
