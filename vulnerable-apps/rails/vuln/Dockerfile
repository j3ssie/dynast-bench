# Vulnerable variant. Build context is this folder (vuln/), so ../ground-truth
# is structurally outside the context and can never be baked into the image.
FROM ruby:3.3-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev postgresql-client curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV RAILS_ENV=production RACK_ENV=production BUNDLE_WITHOUT=development:test
WORKDIR /app
COPY Gemfile ./
RUN --mount=type=cache,target=/usr/local/bundle/cache bundle install
COPY . .
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000
CMD ["/app/entrypoint.sh"]
