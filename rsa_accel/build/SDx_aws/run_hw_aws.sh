# Running FPGA-accelerated application with warning, it should be run with root rights

if [ $USER != "root" ]; then
    echo "ERROR: FPGA-accelerated application should be run with root rights: sudo sh"
else
    source ../xilinx_aws_run_setup.sh
    ../SDx_alveo/run_hw_test.sh
fi
