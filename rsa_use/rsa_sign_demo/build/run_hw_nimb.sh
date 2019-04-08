
ln -v -s ./SDx_alveo ../../../rsa_accel/build/SDx
source ../../../rsa_accel/build/xilinx_nimb_run_setup.sh
./RSA_Sign_Demo -hw
rm -f ../../../rsa_accel/build/SDx
