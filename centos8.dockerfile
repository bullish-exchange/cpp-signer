FROM centos:8
#docker run -it -v /path/to/cpp-signer:/root centos:8 /bin/bash
RUN cd /etc/yum.repos.d && \
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

RUN dnf update -y
RUN dnf install -y cmake && \
    dnf install -y gcc-toolset-10-gcc-c++ && \
    dnf install -y git && \
    dnf install -y perl && \
    dnf install -y wget && \
    dnf install -y zlib-devel

RUN source scl_source enable gcc-toolset-10 && \
    wget https://ftp.openssl.org/source/openssl-1.1.1q.tar.gz && \
    tar -xzvf openssl-1.1.1q.tar.gz && \
    cd openssl-1.1.1q && \
    ./config --prefix=/usr/local --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic && \
    make && \
    make install && \
    cd ..

COPY . cpp-signer

RUN source scl_source enable gcc-toolset-10 && \
    update-alternatives --install /usr/bin/c++ c++ /opt/rh/gcc-toolset-10/root/usr/bin/g++ 10 && \
    export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64 && \
    cd cpp-signer && \
    cmake -DEOSIO_R1_KEY_ENABLE_TEST=ON -DEOSIO_R1_KEY_ENABLE_EXAMPLE=ON -DCMAKE_BUILD_TYPE=Release -S. -Bbuild -DOPENSSL_ROOT_DIR=/usr/local && cmake --build build

# python tool to generate JWT
RUN git clone https://github.com/bullish-exchange/api-examples.git
RUN dnf install -y python3-pip
RUN cd api-examples && pip3 install -r requirements.txt

