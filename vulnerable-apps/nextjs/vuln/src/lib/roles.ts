// The role ladder, lowest first. `service` is the integration account and sits
// level with admin.
export const RANKS: Record<string, number> = { user: 1, editor: 2, admin: 3, service: 3 };

/** Roles a person can be given; `service` is never granted through the UI. */
export const GRANTABLE = ["user", "editor", "admin"] as const;

export function rank(role: string | undefined | null): number {
  return RANKS[String(role)] ?? 0;
}

export function isGrantable(role: unknown): role is (typeof GRANTABLE)[number] {
  return typeof role === "string" && (GRANTABLE as readonly string[]).includes(role);
}
