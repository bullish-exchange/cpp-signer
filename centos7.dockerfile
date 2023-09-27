FROM centos:7

# docker build -t cpp-signer-centos7 -f ./centos7.dockerfile .

# In case the docker env can't recognize the certificate
# Please remove this line if your env does not need this!

RUN echo "sslverify=false" >> /etc/yum.conf

RUN yum update -y
RUN yum install -y make which && \
    yum install -y gcc gcc-c++ && \
    yum install -y git perl perl-IPC-Cmd perl-Test-Simple curl bzip2 && \
    yum install -y zlib-devel

RUN yum remove -y cmake

RUN curl -fsSLOk https://github.com/Kitware/CMake/releases/download/v3.26.4/cmake-3.26.4-linux-x86_64.sh && \
    echo "413e59e94b9a3eed2d73f8fc85520d505e514e95005471504d8bebe844970d67 cmake-3.26.4-linux-x86_64.sh" | sha256sum -c - && \
    bash cmake-3.26.4-linux-x86_64.sh --skip-license --prefix=/usr/local

RUN curl -fsSLOk "https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.bz2" && \
    echo "8681f175d4bdb26c52222665793eef08490d7758529330f98d3b29dd0735bccc boost_1_78_0.tar.bz2" | sha256sum -c - && \
    tar -xjf "boost_1_78_0.tar.bz2" && \
    cd "boost_1_78_0" && \
    sed -i 's/#!\/bin\/sh/#!\/usr\/bin\/bash/' ./bootstrap.sh && \
    sed -i 's/#!\/bin\/sh/#!\/usr\/bin\/bash/' ./tools/build/src/engine/build.sh && \
    ./bootstrap.sh --prefix=/usr/local && \
    ./b2 --with-iostreams --with-date_time --with-filesystem --with-system --with-program_options --with-chrono --with-test -j$(nproc) install && \
    cd .. && \
    rm -rf "boost_1_78_0.tar.bz2" "boost_1_78_0"

RUN curl -fsSLOk https://ftp.openssl.org/source/openssl-3.0.8.tar.gz && \
    echo "6c13d2bf38fdf31eac3ce2a347073673f5d63263398f1f69d0df4a41253e4b3e openssl-3.0.8.tar.gz" | sha256sum -c - && \
    tar -xzvf openssl-3.0.8.tar.gz && \
    cd openssl-3.0.8 && \
    ./config --prefix=/usr/local --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic && \
    make -j$(nproc) && \
    make install && \
    cd ..

RUN rm -rf cpp-signer

COPY . cpp-signer

RUN cd cpp-signer && \
    mkdir -p build && \
    cd build && \
    cmake -DEOSIO_R1_KEY_ENABLE_TEST=ON -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/usr/local .. && \
    make -j$(nproc) && \
    ctest . && \
    echo "All good."

