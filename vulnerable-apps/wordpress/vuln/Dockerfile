FROM php:8.3-cli
WORKDIR /app
COPY . /app
RUN chmod +x /app/entrypoint.sh
EXPOSE 3000
HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD php -r '$j=@file_get_contents("http://127.0.0.1:3000/api/_verify/health"); exit(strpos($j,"ok")!==false?0:1);'
CMD ["/app/entrypoint.sh"]
