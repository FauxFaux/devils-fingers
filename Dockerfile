FROM clux/muslrust

ADD libpcap-1.8.1.tar .

RUN apt-get update
RUN apt-get install -y flex bison
RUN cd libpcap-1.8.1 && autoreconf -fvi && \
    CC="musl-gcc -fPIC -pie" LDFLAGS="-L$PREFIX/lib" CFLAGS="-I$PREFIX/include" \
        ./configure --prefix=$PREFIX --disable-shared
RUN cd libpcap-1.8.1 && make -j$(nproc) && make install

# warm caches
RUN cd /tmp && \
    USER=foo cargo init --bin awa && \
    cd awa && \
    printf 'failure = "*"\nclap = "*"\nzstd = "*"' >> Cargo.toml && \
    cargo fetch
