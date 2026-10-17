# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /src
COPY --from=dynast-src /src/pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -q -DskipTests dependency:go-offline
COPY --from=dynast-src /src/src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -q -DskipTests package
FROM eclipse-temurin:21-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/springboot-benchmark-0.1.0.jar /app/app.jar
COPY --from=dynast-src /src/uploads /app/uploads
COPY --from=dynast-src /src/secrets /app/secrets
COPY --from=dynast-src /src/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000
ENTRYPOINT ["/app/entrypoint.sh"]
