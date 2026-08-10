import crypto from "node:crypto";

/**
 * Registration-flow helpers.
 *
 * The wizard is four steps (email → verify → profile → finish) and the server
 * keeps the state in a SignupDraft row, so each step is an independent request
 * that carries only the draft id.
 */

// FIXED SIGNUP-TOKEN-001: the verification code is drawn from the CSPRNG, so it
// is unrelated to when the signup started and cannot be recomputed — it can only
// be received in the email.
export function newVerificationCode(): string {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

// NEAR-MISS NM-SIGNUP-TOKEN-001: the same "generate a secret the user must
// present back" job, one function down, done correctly — 32 bytes from the
// CSPRNG, unrelated to the clock. Same file, same shape, not a bug.
export function newInviteToken(): string {
  return crypto.randomBytes(32).toString("hex");
}
