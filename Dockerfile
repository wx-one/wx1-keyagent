# wx1-keyagent: meta -> nginx-Modul, ausgeliefert mit dem passenden nginx.
#   docker build --build-context meta=../../metalanguage -t wx/wx1-keyagent .
ARG NGINX_VERSION=1.26.3

FROM debian:trixie AS build
ARG NGINX_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake curl ca-certificates libpq-dev libcurl4-openssl-dev \
      libssl-dev libpcre2-dev zlib1g-dev libyaml-dev \
    && rm -rf /var/lib/apt/lists/*

# meta selbst, aus seinem Git-Stand
ARG META_PATH=/opt/meta
COPY --from=meta . ${META_PATH}
RUN cd ${META_PATH} && cmake -DCMAKE_BUILD_TYPE=Release . >/dev/null \
    && make -j"$(nproc)" meta meta-http >/dev/null 2>&1 && ln -s ${META_PATH} /meta \
    && cat ${META_PATH}/META_COMMIT

RUN curl -fsSL https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar -xz -C /

COPY src /src
# die eigenen Header einzeln uebersetzen (sie enthalten meta-Syntax), dann das Programm
RUN cd /src && /meta/meta -s -I /src -I /usr/include/postgresql -emit-each /addon-h *.h \
    && /meta/meta -s -I /src -I /usr/include/postgresql -module /addon main.c \
    && cp /addon-h/*.h /addon/
RUN cd /nginx-${NGINX_VERSION} \
    && ./configure --prefix=/opt/nginx --with-compat --with-http_ssl_module --with-cc-opt="-Wno-error -I/usr/include/postgresql -I/addon" \
         --with-ld-opt="-lpq -lcurl -lcrypto -lyaml" \
         --without-http_rewrite_module --without-http_gzip_module \
         --add-dynamic-module=/addon >/dev/null \
    && make -j"$(nproc)" >/dev/null && make install >/dev/null \
    && cp objs/ngx_http_meta_module.so /opt/nginx/modules/

FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 libcurl4t64 libssl3t64 libpcre2-8-0 zlib1g libyaml-0-2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/nginx /opt/nginx
COPY --from=build /meta/meta-http /usr/local/bin/meta-http
ENV META_HTTP_NGINX=/opt/nginx/sbin/nginx META_HTTP_PREFIX=/var/lib/wx1-keyagent/nginx
# nicht als root: nginx braucht keine Rechte, und Master und Worker laufen als ein Benutzer
RUN useradd --system --home /var/lib/wx1-keyagent wx1ka && mkdir -p /var/lib/wx1-keyagent/nginx \
    && chown -R wx1ka /var/lib/wx1-keyagent
USER wx1ka
CMD ["meta-http", "/opt/nginx/modules/ngx_http_meta_module.so"]
