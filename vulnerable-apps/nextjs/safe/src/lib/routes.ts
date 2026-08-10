/**
 * The client's API route registry.
 *
 * Every browser-side call goes through `api()` rather than a literal URL. This
 * is an ordinary API-client shape - one place to change a base path, one place
 * to see the surface - and it is also why grepping the served HTML or a bundle
 * for "/api/posts/search" finds nothing: the full path never exists as a string
 * until the call is made. A tool that parses or executes the JS resolves it
 * fine; a tool that pattern-matches text does not.
 */

export const API_BASE = "/api";

/** Path segments per endpoint, joined at call time. */
export const ROUTES = {
  login: ["auth", "login"],
  logout: ["auth", "logout"],
  me: ["users", "me"],
  nav: ["nav"],
  postSearch: ["posts", "search"],
  comments: ["comments"],
  invites: ["invites"],
  seats: ["billing", "seats"],
  preview: ["preview"],
  cache: ["cache"],
  reports: ["reports", "admin-summary"],
  attachments: ["attachments", "download"],
  promote: ["users", "{id}", "promote"],
  settingsImport: ["settings", "import"],
  syncToken: ["integrations", "token"],
  sync: ["integrations", "sync"],
  adminUsers: ["admin", "users"],
  signupStart: ["signup", "start"],
  signupVerify: ["signup", "verify"],
  signupProfile: ["signup", "profile"],
  signupComplete: ["signup", "complete"],
  signupResend: ["signup", "resend"],
  signupDraft: ["signup", "draft"],
} satisfies Record<string, string[]>;

export type RouteName = keyof typeof ROUTES;

export function api(name: RouteName, ...extra: (string | number)[]): string {
  return [API_BASE, ...ROUTES[name], ...extra.map(String)].join("/");
}
