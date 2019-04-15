#!/bin/sh

if [ -z "$OPENSSL_DIR" ]; then
	echo "OPENSSL_DIR is not set, please source ../../../rsa_accel/build/xilinx_xxx_setup.sh script."
	exit 2
fi

g++ ../src/aws_rsa_engine.cpp\
    ../src/aws_rsa_fpga.cpp\
    -I../../../rsa_accel/src -I$XILINX_VIVADO/include -I$OPENSSL_DIR/.. -I$OPENSSL_DIR/include -I$OPENSSL_DIR/crypto/include\
    -DAWS_RSA_DIAGNOSTIC_MESSAGE=1 -DMAX_RSA_BITS=2048 -DUNIT_COUNT=400\
    -O3 -DNDEBUG -std=c++0x -shared -fPIC -pthread\
    -lpthread -lgmp -lOpenCL\
    -o ZoTech_AWS_RSA_Engine.so
