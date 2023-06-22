FROM centos:8

# docker build -t cpp-signer-centos8 -f ./centos8.dockerfile .

RUN cd /etc/yum.repos.d && \
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# In case the docker env can't recognize the certificate
# Please remove this line if your env does not need this!

RUN echo "sslverify=false" >> /etc/yum.conf

RUN dnf update -y
RUN dnf install -y cmake make && \
    dnf install -y gcc gcc-c++ && \
    dnf install -y git perl curl bzip2 && \
    dnf install -y zlib-devel

RUN curl -fsSLOk "https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.bz2" && \
    echo "8681f175d4bdb26c52222665793eef08490d7758529330f98d3b29dd0735bccc boost_1_78_0.tar.bz2" | sha256sum -c - && \
    tar -xjf "boost_1_78_0.tar.bz2" && \
    cd "boost_1_78_0" && \
    ./bootstrap.sh --prefix=/usr/local && \
    ./b2 --with-iostreams --with-date_time --with-filesystem --with-system --with-program_options --with-chrono --with-test -j$(nproc) install && \
    cd .. && \
    rm -rf "boost_1_78_0.tar.bz2" "boost_1_78_0"

RUN curl -fsSLOk https://ftp.openssl.org/source/openssl-1.1.1q.tar.gz && \
    echo "d7939ce614029cdff0b6c20f0e2e5703158a489a72b2507b8bd51bf8c8fd10ca openssl-1.1.1q.tar.gz" | sha256sum -c - && \
    tar -xzvf openssl-1.1.1q.tar.gz && \
    cd openssl-1.1.1q && \
    ./config --prefix=/usr/local --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic && \
    make -j$(nproc) && \
    make install && \
    cd ..

RUN rm -rf cpp-signer

COPY . cpp-signer

RUN cd cpp-signer && \
    rm -rf build/* && \
    mkdir -p build && \
    cd build && \
    cmake -DEOSIO_R1_KEY_ENABLE_TEST=ON -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/usr/local .. && \
    make -j$(nproc) && \
    ctest . && \
    echo "All good."

