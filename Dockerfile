# wx-keyagent: meta -> nginx-Modul, ausgeliefert mit dem passenden nginx.
#   docker build --build-context meta=../../metalanguage -t wx/keyagent-meta .
ARG NGINX_VERSION=1.26.3

FROM debian:trixie AS build
ARG NGINX_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake curl ca-certificates libpq-dev libcurl4-openssl-dev \
      libssl-dev libpcre2-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# meta selbst, aus seinem Git-Stand
ARG META_PATH=/opt/meta
COPY --from=meta . ${META_PATH}
RUN cd ${META_PATH} && cmake -DCMAKE_BUILD_TYPE=Release . >/dev/null \
    && make -j"$(nproc)" meta meta-http >/dev/null 2>&1 && ln -s ${META_PATH} /meta \
    && cat ${META_PATH}/META_COMMIT

RUN curl -fsSL https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar -xz -C /

COPY src /src
RUN /meta/meta -s -I /src -I /usr/include/postgresql -module /addon /src/main.c
RUN cd /nginx-${NGINX_VERSION} \
    && ./configure --prefix=/opt/nginx --with-compat --with-cc-opt="-Wno-error -I/usr/include/postgresql" \
         --with-ld-opt="-lpq -lcurl -lcrypto" \
         --without-http_rewrite_module --without-http_gzip_module \
         --add-dynamic-module=/addon >/dev/null \
    && make -j"$(nproc)" >/dev/null && make install >/dev/null \
    && cp objs/ngx_http_meta_module.so /opt/nginx/modules/

FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 libcurl4t64 libssl3t64 libpcre2-8-0 zlib1g ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/nginx /opt/nginx
COPY --from=build /meta/meta-http /usr/local/bin/meta-http
ENV META_HTTP_NGINX=/opt/nginx/sbin/nginx META_HTTP_PREFIX=/var/lib/wx-keyagent/nginx
# nicht als root: nginx braucht keine Rechte, und Master und Worker laufen als ein Benutzer
RUN useradd --system --home /var/lib/wx-keyagent wxka && mkdir -p /var/lib/wx-keyagent/nginx \
    && chown -R wxka /var/lib/wx-keyagent
USER wxka
CMD ["meta-http", "/opt/nginx/modules/ngx_http_meta_module.so"]
