#!/usr/bin/env sh
set -eu
exec java ${JAVA_OPTS:-} -jar /app/app.jar
