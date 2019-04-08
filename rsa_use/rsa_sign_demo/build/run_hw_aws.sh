# Running FPGA-accelerated application with warning, it should be run with root rights

if [ $USER != "root" ]; then
    echo "ERROR: FPGA-accelerated application should be run with root rights: sudo sh"
else
	ln -v -s ./SDx_aws ../../../rsa_accel/build/SDx
    source ../../../rsa_accel/build/xilinx_aws_run_setup.sh
    ./RSA_Sign_Demo -hw
	rm -f ../../../rsa_accel/build/SDx
fi
