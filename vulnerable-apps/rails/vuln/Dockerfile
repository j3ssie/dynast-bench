# Vulnerable variant. Build context is this folder (vuln/), so ../ground-truth
# is structurally outside the context and can never be baked into the image.

# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM ruby:3.3-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev postgresql-client curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV RAILS_ENV=production RACK_ENV=production BUNDLE_WITHOUT=development:test
WORKDIR /app
COPY --from=dynast-src /src/Gemfile ./
RUN --mount=type=cache,target=/usr/local/bundle/cache bundle install
COPY --from=dynast-src /src/ .
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000
CMD ["/app/entrypoint.sh"]
