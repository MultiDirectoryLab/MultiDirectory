FROM alpine:3.20 AS builder

RUN apk add --no-cache --virtual .build-deps \
      build-base \
      lmdb-dev \
      openssl-dev \
      boost-dev \
      autoconf automake libtool \
      git ragel bison flex \
      lua5.4-dev \
      curl-dev

RUN apk add --no-cache \
      lua \
      lua-dev \
      lmdb \
      boost-libs \
      openssl-libs-static \
      curl \
      libstdc++

RUN git clone https://github.com/PowerDNS/pdns.git /pdns
WORKDIR /pdns

RUN git submodule init &&\
    git submodule update &&\
    git checkout auth-5.0.1

RUN autoreconf -vi

RUN mkdir /build && \
    ./configure \
      --sysconfdir=/etc/powerdns \
      --enable-option-checking=fatal \
      --with-dynmodules='lmdb' \
      --with-modules='' \
      --with-unixodbc-lib=/usr/lib/$(dpkg-architecture -q DEB_BUILD_GNU_TYPE) && \
    make clean && \
    make $MAKEFLAGS -C ext &&\
    make $MAKEFLAGS -C modules &&\
    make $MAKEFLAGS -C pdns && \
    make -C pdns install DESTDIR=/build &&\ 
    make -C modules install DESTDIR=/build &&\ 
    make clean && \
    strip /build/usr/local/bin/* /build/usr/local/sbin/* /build/usr/local/lib/pdns/*.so

# ====================================================================================================
    
FROM alpine:3.20 AS runtime

COPY --from=builder /build /

RUN apk add --no-cache \
    lua \
    lua-dev \
    lmdb \
    boost-libs \
    openssl-libs-static \
    curl \
    libstdc++

RUN mkdir -p /etc/powerdns/pdns.d /var/run/pdns /var/lib/powerdns /etc/powerdns/templates.d /var/lib/pdns-lmdb

COPY ./pdns.conf /etc/powerdns/pdns.conf

EXPOSE 8082/tcp

CMD ["/usr/local/sbin/pdns_server"]