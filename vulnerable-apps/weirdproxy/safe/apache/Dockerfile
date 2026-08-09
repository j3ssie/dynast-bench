FROM httpd:2.4
RUN sed -i \
    -e 's|^#LoadModule proxy_module|LoadModule proxy_module|' \
    -e 's|^#LoadModule proxy_http_module|LoadModule proxy_http_module|' \
    -e 's|^#LoadModule headers_module|LoadModule headers_module|' \
    /usr/local/apache2/conf/httpd.conf \
 && echo 'Include conf/extra/proxy-bench.conf' >> /usr/local/apache2/conf/httpd.conf
COPY proxy-bench.conf /usr/local/apache2/conf/extra/proxy-bench.conf
EXPOSE 80
