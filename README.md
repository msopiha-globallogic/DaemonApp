To make this buildable:
1. Install OpenSSL version 1.1.1d

    Go to https://www.openssl.org/source/, download openssl-1.1.1d archive, unzip.

    wget https://www.openssl.org/source/openssl-1.1.1d.tar.gz

2.  cd <openssl_source_dir>

3.  ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)
    make -jx

2. Configure your path to openssl directory in makefile (the openssl that was built in step 1)
3. Use 'make' command to build.
