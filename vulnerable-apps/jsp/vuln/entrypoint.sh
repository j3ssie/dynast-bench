#!/usr/bin/env sh
set -eu
printf 'XXE-LOCAL-FILE-MARKER-jsp-42\n' > /tmp/jsp-xxe-secret.txt
(
  while [ ! -d /usr/local/tomcat/webapps/ROOT ]; do sleep 1; done
  mkdir -p /usr/local/tomcat/webapps/ROOT/uploads /usr/local/tomcat/webapps/ROOT/downloads
) &
exec catalina.sh run
