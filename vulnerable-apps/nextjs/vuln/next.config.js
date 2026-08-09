/** @type {import('next').NextConfig} */
const nextConfig = {
  // Benchmark app: keep boot resilient regardless of lint/type state.
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: true },
  // NOTE (planted, next/image SSRF surface — see ground-truth notes): overly
  // broad remote image patterns. Not scored in v1 but left as realistic config.
  images: { remotePatterns: [{ protocol: "http", hostname: "**" }] },
  // VULN SOURCEMAP-001 (CWE-540): ships browser source maps in the production
  // build. Every /_next/static/chunks/*.js has a public *.js.map carrying the
  // original TypeScript in `sourcesContent`, including comments and file paths.
  productionBrowserSourceMaps: true,
};
module.exports = nextConfig;
