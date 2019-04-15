# Building sw part only of AWS FPGA-accelerated application
g++ ../../src/rsa_test_aws.cpp\
    ../../src/rsa_gmp.cpp\
    ../../src/rsa_pow.cpp\
    ../../src/rsa_seq.cpp\
    ../../src/rsa_int.cpp\
    ../../src/rsa.cpp\
    -I$XILINX_VIVADO/include\
    -DMAX_RSA_BITS=2048 -DUSE_OPENCL -DUNIT_COUNT=400\
    -O3 -DNDEBUG -std=c++0x -pthread\
    -lpthread -lgmp -lOpenCL\
    -o test_rsa_hls
