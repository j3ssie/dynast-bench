import Redis from "ioredis";

const g = globalThis as unknown as { redis?: Redis };
export const redis =
  g.redis || new Redis(process.env.REDIS_URL || "redis://redis:6379", { lazyConnect: false });
g.redis = redis;
