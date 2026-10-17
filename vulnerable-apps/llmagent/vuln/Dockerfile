# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM node:22-slim
WORKDIR /app
COPY --from=dynast-src /src/package.json ./
RUN --mount=type=cache,target=/root/.npm npm install --omit=dev
COPY --from=dynast-src /src/ .
ENV PORT=3000 LLM_BACKEND=stub
EXPOSE 3000
CMD ["node","src/app.mjs"]
