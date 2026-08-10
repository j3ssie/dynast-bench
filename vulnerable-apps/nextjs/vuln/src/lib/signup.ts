import crypto from "node:crypto";

/**
 * Registration-flow helpers.
 *
 * The wizard is four steps (email → verify → profile → finish) and the server
 * keeps the state in a SignupDraft row, so each step is an independent request
 * that carries only the draft id.
 */

// VULN SIGNUP-TOKEN-001 (CWE-330/CWE-640): the emailed verification code is
// derived from the clock, not from a CSPRNG. Anyone who can start a signup for
// an address — or who knows roughly when one was started — can recompute the
// code instead of receiving it, which turns "prove you own this mailbox" into
// arithmetic.
export function newVerificationCode(): string {
  return String(Math.floor(Date.now() / 1000)).slice(-6);
}

// NEAR-MISS NM-SIGNUP-TOKEN-001: the same "generate a secret the user must
// present back" job, one function down, done correctly — 32 bytes from the
// CSPRNG, unrelated to the clock. Same file, same shape, not a bug.
export function newInviteToken(): string {
  return crypto.randomBytes(32).toString("hex");
}
