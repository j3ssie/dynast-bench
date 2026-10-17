# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM node:22-alpine
WORKDIR /app
COPY --from=dynast-src /src/server.mjs /app/server.mjs
EXPOSE 9000
CMD ["node", "/app/server.mjs"]
