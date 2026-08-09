/** @type {import('next').NextConfig} */
const nextConfig = {
  // Benchmark app: keep boot resilient regardless of lint/type state.
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: true },
  // NOTE (planted, next/image SSRF surface — see ground-truth notes): overly
  // broad remote image patterns. Not scored in v1 but left as realistic config.
  images: { remotePatterns: [{ protocol: "http", hostname: "**" }] },
  // FIXED SOURCEMAP-001: no browser source maps in the production build (Next's
  // default). Nothing under /_next/static/chunks/ has a public *.js.map, so the
  // original TypeScript never ships to the client.
};
module.exports = nextConfig;
