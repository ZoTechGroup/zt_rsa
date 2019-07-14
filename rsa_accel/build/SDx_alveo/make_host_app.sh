#!/bin/sh

if [ -z "$OPENSSL_DIR" ]; then
    echo "OPENSSL_DIR is not set, please source ../xilinx_xxx_setup.sh script."
    exit 2
fi

# Building sw part only of AWS FPGA-accelerated application (-std=c++1y is synonym to s-std=c++14)
g++ ../../src/rsa_test.cpp\
    ../../src/rsa_gmp.cpp\
    ../../src/rsa_pow.cpp\
    ../../src/rsa_seq.cpp\
    ../../src/rsa_int.cpp\
    ../../src/rsa.cpp\
    ../../src/rsa_pkcs.cpp\
    -I$XILINX_VIVADO/include\
    -I$OPENSSL_DIR/include\
    -DMAX_RSA_BITS=2048 -DUSE_OPENCL\
    -O3 -DNDEBUG -std=c++1y -pthread\
    -lpthread -lgmp -lOpenCL -L$OPENSSL_DIR -lcrypto\
    -o test_rsa_hls
