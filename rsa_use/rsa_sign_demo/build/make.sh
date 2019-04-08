#!/bin/sh

if [ -z "$OPENSSL_DIR" ]; then
	echo "OPENSSL_DIR is not set, please source ../../../rsa_accel/build/xilinx_xxx_setup.sh script."
	exit 2
fi

g++ ../src/RSA_Sign_Demo.cpp\
    -I$OPENSSL_DIR/.. -I$OPENSSL_DIR/include\
    -O3 -DNDEBUG -std=c++0x -pthread\
    -lpthread -lcrypto -L/usr/local/lib64\
    -o RSA_Sign_Demo 
