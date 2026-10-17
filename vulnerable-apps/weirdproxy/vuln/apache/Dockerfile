# The build context with its answer-key comments blanked out
# (dynast-bench/tools/annotations/strip.mjs). Every COPY of app files below
# reads from this stage, never from the raw context.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dynast-src
COPY --from=dynast-annotations strip.mjs /opt/dynast/strip.mjs
COPY . /src
RUN node /opt/dynast/strip.mjs /src

FROM httpd:2.4
RUN sed -i \
    -e 's|^#LoadModule proxy_module|LoadModule proxy_module|' \
    -e 's|^#LoadModule proxy_http_module|LoadModule proxy_http_module|' \
    -e 's|^#LoadModule headers_module|LoadModule headers_module|' \
    /usr/local/apache2/conf/httpd.conf \
 && echo 'Include conf/extra/proxy-bench.conf' >> /usr/local/apache2/conf/httpd.conf
COPY --from=dynast-src /src/proxy-bench.conf /usr/local/apache2/conf/extra/proxy-bench.conf
EXPOSE 80
