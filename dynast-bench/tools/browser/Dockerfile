# The headless browser the ground-truth PoCs drive.
#
# Built once and shared by every app, so it lives here rather than in any single
# vulnerable-apps/<app>/.
#
# Chromium comes from Debian rather than from puppeteer's own download, and the
# client is puppeteer-core rather than puppeteer, for one reason: Chrome for
# Testing publishes no linux-arm64 build, so the bundled-browser route silently
# forces every Apple Silicon machine into amd64 emulation. Debian ships chromium
# for both arches, so this image is native wherever it is built.
FROM node:22-slim

ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/drive
RUN npm install --omit=dev --no-audit --no-fund puppeteer-core@23

COPY drive.mjs /opt/drive/drive.mjs

# The PoCs pass only flags, never a command.
ENTRYPOINT ["node", "/opt/drive/drive.mjs"]
